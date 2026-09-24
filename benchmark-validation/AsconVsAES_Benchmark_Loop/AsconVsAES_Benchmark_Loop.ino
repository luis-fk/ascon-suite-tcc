#include <ASCON.h>
#include "mbedtls/gcm.h"
#include <string.h>

#define MAX_PLAINTEXT 64
#define RUNS 100                 // N execucoes independentes por tamanho
#define ITERATIONS_PER_RUN 2000  // medidas dentro de cada execucao (igual ao single-run)

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t initializationVector[12];           // IV do GCM (12 B = 96 bits, caso nativo/rapido)
static uint8_t plaintext[MAX_PLAINTEXT];
static uint8_t ciphertext[MAX_PLAINTEXT + ASCON128_TAG_SIZE];
static uint8_t aesCiphertext[MAX_PLAINTEXT];
static uint8_t aesTag[16];

struct CycleStatistics {
  uint32_t minCycles;
  uint32_t maxCycles;
  double   meanCycles;
};

// Agregado ENTRE as N execucoes, para UM algoritmo (metrica: piso por execucao).
struct FloorSummary {
  uint32_t minFloor;     // menor piso entre as execucoes
  uint32_t maxFloor;     // maior piso entre as execucoes
  double   sumFloors;    // soma dos pisos (para a media)
  int      runsAtFloor;  // quantas execucoes atingiram minFloor
};

// Agregado da RAZAO AES/Ascon entre as N execucoes.
struct RatioSummary {
  double minRatio;
  double maxRatio;
  double sumRatios;
  int    runsAsconFaster;   // execucoes em que o piso do Ascon ficou abaixo do do AES
};

// Resultado completo de um tamanho de payload.
struct SizeComparison {
  FloorSummary ascon;
  FloorSummary aes;
  RatioSummary ratio;
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
  fillVarying(key,                  ASCON128_KEY_SIZE,            iteration, 31, 7, 1);
  fillVarying(nonce,                ASCON128_NONCE_SIZE,          iteration, 17, 3, 0);
  fillVarying(initializationVector, sizeof(initializationVector), iteration, 19, 5, 0);
  fillVarying(plaintext,            messageLength,                iteration, 13, 5, 0);
}

static double cyclesToMicroseconds(double cycles)
{
  return cycles / (double) getCpuFrequencyMhz();
}

// ----- Ascon-128a (software) -----
static CycleStatistics benchmarkAscon(size_t messageLength, int iterations)
{
  size_t ciphertextLength = 0;
  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, messageLength, NULL, 0, nonce, key);
    uint32_t endCycles = ESP.getCycleCount();

    uint32_t cycles = endCycles - startCycles;

    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum += (double) cycles;
  }

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = cycleSum / iterations;

  return stats;
}

// ----- AES-128-GCM (mbedTLS; bloco AES por hardware no ESP32) -----
static CycleStatistics benchmarkAES(size_t messageLength, int iterations)
{
  mbedtls_gcm_context gcmContext;
  mbedtls_gcm_init(&gcmContext);
  mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);  // chave fixada 1x (amortizada)

  uint32_t minCycles = 0xFFFFFFFFu, maxCycles = 0;
  double cycleSum = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int iteration = 0; iteration < 16; iteration++) {
    varyInputs(iteration, messageLength);
    mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, messageLength, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
  }

  for (int iteration = 0; iteration < iterations; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();
    mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, messageLength, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
    uint32_t endCycles = ESP.getCycleCount();

    uint32_t cycles = endCycles - startCycles;

    if (cycles < minCycles) {
      minCycles = cycles;
    }

    if (cycles > maxCycles) {
      maxCycles = cycles;
    }

    cycleSum += (double) cycles;
  }

  mbedtls_gcm_free(&gcmContext);

  CycleStatistics stats;

  stats.minCycles  = minCycles;
  stats.maxCycles  = maxCycles;
  stats.meanCycles = cycleSum / iterations;

  return stats;
}

static void initFloorSummary(FloorSummary *summary)
{
  summary->minFloor    = 0xFFFFFFFFu;
  summary->maxFloor    = 0;
  summary->sumFloors   = 0.0;
  summary->runsAtFloor = 0;
}

static void accumulateFloor(FloorSummary *summary, uint32_t floor)
{
  if (floor < summary->minFloor) {
    summary->minFloor = floor;
    summary->runsAtFloor = 1;          // novo piso: esta rodada e a primeira a atingi-lo
  }
  else if (floor == summary->minFloor) {
    summary->runsAtFloor++;
  }

  if (floor > summary->maxFloor) {
    summary->maxFloor = floor;
  }

  summary->sumFloors += (double) floor;
}

// Repete o comparativo 'runs' vezes para um tamanho e agrega os pisos e a razao.
static SizeComparison repeatComparison(size_t messageLength, int runs, int iterationsPerRun)
{
  SizeComparison comparison;

  initFloorSummary(&comparison.ascon);
  initFloorSummary(&comparison.aes);

  comparison.ratio.minRatio        = 1.0e9;
  comparison.ratio.maxRatio        = 0.0;
  comparison.ratio.sumRatios       = 0.0;
  comparison.ratio.runsAsconFaster = 0;

  for (int run = 0; run < runs; run++) {
    CycleStatistics asconStats = benchmarkAscon(messageLength, iterationsPerRun);
    CycleStatistics aesStats   = benchmarkAES(messageLength, iterationsPerRun);

    uint32_t asconFloor = asconStats.minCycles;
    uint32_t aesFloor   = aesStats.minCycles;

    accumulateFloor(&comparison.ascon, asconFloor);
    accumulateFloor(&comparison.aes,   aesFloor);

    double runRatio = (double) aesFloor / (double) asconFloor;

    if (runRatio < comparison.ratio.minRatio) {
      comparison.ratio.minRatio = runRatio;
    }

    if (runRatio > comparison.ratio.maxRatio) {
      comparison.ratio.maxRatio = runRatio;
    }

    comparison.ratio.sumRatios += runRatio;

    if (asconFloor < aesFloor) {
      comparison.ratio.runsAsconFaster++;
    }

    Serial.print(".");   // progresso (fora da medicao)
    delay(1);            // cede o processador entre rodadas (alimenta o watchdog)
  }

  Serial.println();
  return comparison;
}

static void printFloorLine(const char *label, FloorSummary summary, int runs)
{
  double meanFloor = summary.sumFloors / runs;

  Serial.print("    "); Serial.print(label);
  Serial.print(": piso min "); Serial.print(summary.minFloor);
  Serial.print(" | piso max "); Serial.print(summary.maxFloor);
  Serial.print(" | spread "); Serial.print(summary.maxFloor - summary.minFloor);
  Serial.print(" | media "); Serial.print(meanFloor, 1);
  Serial.print(" (~"); Serial.print(cyclesToMicroseconds(meanFloor), 2); Serial.print(" us)");
  Serial.print(" | rodadas no piso "); Serial.print(summary.runsAtFloor);
  Serial.print("/"); Serial.println(runs);
}

static void printSizeComparison(size_t messageLength, SizeComparison comparison, int runs)
{
  Serial.print("  "); Serial.print((unsigned) messageLength); Serial.println(" B");

  printFloorLine("Ascon-128a ", comparison.ascon, runs);
  printFloorLine("AES-128-GCM", comparison.aes,   runs);

  Serial.print("    razao AES/Ascon: min "); Serial.print(comparison.ratio.minRatio, 3);
  Serial.print(" | max "); Serial.print(comparison.ratio.maxRatio, 3);
  Serial.print(" | media "); Serial.print(comparison.ratio.sumRatios / runs, 3);
  Serial.print(" | Ascon mais rapido em "); Serial.print(comparison.ratio.runsAsconFaster);
  Serial.print("/"); Serial.print(runs); Serial.println(" rodadas");
}

void setup()
{
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("=== Ascon-128a (sw) vs AES-128-GCM (hw): reprodutibilidade da razao ===");
  Serial.print("CPU: "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
  Serial.print("N (execucoes por tamanho): "); Serial.println(RUNS);
  Serial.print("Medidas por execucao: "); Serial.println(ITERATIONS_PER_RUN);
  Serial.println("Latencia: minimo de ciclos (piso livre de interrupcao) dos dois algoritmos.");
  Serial.println();

  // ----- Sanidade: o caminho AES-GCM realmente cifra e a tag valida -----
  varyInputs(7, 32);
  {
    mbedtls_gcm_context gcmContext;
    mbedtls_gcm_init(&gcmContext);
    int setkeyResult  = mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);
    int encryptResult = mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, 32, initializationVector, 12, NULL, 0, plaintext, aesCiphertext, 16, aesTag);
    uint8_t decryptedOutput[MAX_PLAINTEXT];
    int decryptResult = mbedtls_gcm_auth_decrypt(&gcmContext, 32, initializationVector, 12, NULL, 0, aesTag, 16, aesCiphertext, decryptedOutput);
    mbedtls_gcm_free(&gcmContext);

    bool sanityPassed = (setkeyResult == 0 && encryptResult == 0 && decryptResult == 0 &&
                         memcmp(decryptedOutput, plaintext, 32) == 0);

    Serial.print("Sanidade AES-GCM: ");

    if (sanityPassed) {
      Serial.println("OK (cifra/decifra/tag validam)");
    }
    else {
      Serial.println("FALHOU");
    }
  }
  Serial.println();

  Serial.println("Rodando (cada '.' = 1 execucao; leva cerca de 1 minuto):");

  Serial.print("  16 B: ");
  SizeComparison comparison16 = repeatComparison(16, RUNS, ITERATIONS_PER_RUN);

  Serial.print("  32 B: ");
  SizeComparison comparison32 = repeatComparison(32, RUNS, ITERATIONS_PER_RUN);

  Serial.print("  64 B: ");
  SizeComparison comparison64 = repeatComparison(64, RUNS, ITERATIONS_PER_RUN);

  Serial.println();
  Serial.println("--- Entre execucoes (piso de ciclos por execucao e razao) ---");
  printSizeComparison(16, comparison16, RUNS);
  printSizeComparison(32, comparison32, RUNS);
  printSizeComparison(64, comparison64, RUNS);

  Serial.println();

  int totalAsconFaster = comparison16.ratio.runsAsconFaster
                       + comparison32.ratio.runsAsconFaster
                       + comparison64.ratio.runsAsconFaster;
  int totalRuns = 3 * RUNS;

  Serial.print("Ascon mais rapido que AES-GCM em "); Serial.print(totalAsconFaster);
  Serial.print("/"); Serial.print(totalRuns); Serial.println(" execucoes (todos os tamanhos)");

  if (totalAsconFaster == totalRuns) {
    Serial.println(">>> Vantagem do Ascon reproduzida em todas as execucoes <<<");
  }
  else {
    Serial.println(">>> Houve execucoes sem vantagem do Ascon (ver acima) <<<");
  }
}

void loop()
{
  delay(1000);  // o teste roda uma vez no setup(); cede o processador
}
