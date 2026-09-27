// Orquestracao: as secoes, na ordem em que aparecem no log, e o veredito.

#include "bench_suite.h"
#include "bench_config.h"
#include "bench_board.h"
#include "bench_inputs.h"
#include "bench_timer.h"
#include "bench_ascon.h"
#include "bench_aes.h"
#include "bench_memory.h"
#include "bench_report.h"

// Pisos guardados entre secoes, indexados como payloadSizes[].
static uint32_t asconEncryptFloor[SIZE_COUNT];
static uint32_t asconDecryptFloor[SIZE_COUNT];
static uint32_t asconEncryptFloorIrqOff[SIZE_COUNT];
static uint32_t gcmEncryptFloor[SIZE_COUNT];
static uint32_t gcmDecryptFloor[SIZE_COUNT];

static StackProbe stackProbe;   // fora da pilha: outra tarefa escreve nele

static int sizeIndex(size_t length)
{
  for (size_t index = 0; index < SIZE_COUNT; index++) {
    if (payloadSizes[index] == length) { return (int) index; }
  }
  return -1;
}

static void printSeparator()
{
  Serial.println();
  Serial.println("---------------------------------------------------------------");
}

// ---------------------------------------------------------------------------
// [1] Autoteste
// ---------------------------------------------------------------------------

static bool sectionSelfCheck()
{
  Serial.println("[1] Autoteste (nada e medido se falhar)");

  uint32_t asconFirstEncrypt = 0, asconFirstDecrypt = 0, aesFirstEncrypt = 0, aesFirstDecrypt = 0;

  bool asconOk = asconSelfCheck(&asconFirstEncrypt, &asconFirstDecrypt);
  bool aesOk   = aesSelfCheck(&aesFirstEncrypt, &aesFirstDecrypt);

  Serial.println();
  Serial.println("  Custo da primeira chamada no firmware (cache fria, 16 B, uma medida):");
  Serial.printf("      Ascon-128a cifra   %u ciclos (%.2f us)\n", (unsigned) asconFirstEncrypt, benchCyclesToMicroseconds(asconFirstEncrypt));
  Serial.printf("      Ascon-128a decifra %u ciclos (%.2f us)\n", (unsigned) asconFirstDecrypt, benchCyclesToMicroseconds(asconFirstDecrypt));
  Serial.printf("      AES-128-GCM cifra  %u ciclos (%.2f us)\n", (unsigned) aesFirstEncrypt,   benchCyclesToMicroseconds(aesFirstEncrypt));
  Serial.printf("      AES-128-GCM decifra %u ciclos (%.2f us)\n", (unsigned) aesFirstDecrypt,  benchCyclesToMicroseconds(aesFirstDecrypt));

  if (!asconOk) { reportProblem("autoteste do Ascon-128a falhou"); }
  if (!aesOk)   { reportProblem("autoteste do AES-128-GCM falhou"); }

  return asconOk && aesOk;
}

// ---------------------------------------------------------------------------
// [2] Memoria
// ---------------------------------------------------------------------------

static void sectionMemory()
{
  Serial.println("[2] Memoria");
  Serial.println("  Heap livre antes e depois de uma operacao completa, por tamanho, e o MENOR valor que um");
  Serial.println("  observador no outro nucleo viu enquanto ela rodava (uma alocacao feita e liberada dentro");
  Serial.println("  da operacao so aparece ali).");

  const BenchSpec *specs[] = { &asconEncryptSpec, &asconDecryptSpec, &aesGcmEncryptSpec, &aesGcmDecryptSpec };
  bool asconClean    = true;
  bool aesClean      = true;
  bool watcherFailed = false;

  for (size_t sizeIdx = 0; sizeIdx < SIZE_COUNT; sizeIdx++) {
    size_t length = payloadSizes[sizeIdx];

    for (size_t specIdx = 0; specIdx < 4; specIdx++) {
      HeapProbe probe = memoryHeapProbe(specs[specIdx], length);
      int32_t   delta = (int32_t) probe.freeAfter - (int32_t) probe.freeBefore;
      bool      transient = probe.minimumDuring < probe.freeBefore;

      Serial.printf("  %2u B  %s  heap antes %u | menor durante %u | depois %u (delta %d) | %u amostras | %s\n",
                    (unsigned) length, specs[specIdx]->name,
                    (unsigned) probe.freeBefore, (unsigned) probe.minimumDuring,
                    (unsigned) probe.freeAfter, (int) delta, (unsigned) probe.samples,
                    !probe.watched ? "OBSERVADOR NAO RODOU" :
                    transient ? "ALOCACAO TRANSITORIA" : "sem alocacao");

      if (!probe.watched) { watcherFailed = true; }

      if (delta != 0 || transient) {
        if (specIdx < 2) { asconClean = false; } else { aesClean = false; }
      }
    }
  }

  if (watcherFailed) { reportProblem("o observador de heap nao rodou; a deteccao de alocacao transitoria nao vale"); }
  if (!asconClean)   { reportProblem("o Ascon-128a alocou memoria dinamica (RNF6)"); }
  if (!aesClean)   { reportNote("o AES-GCM alocou memoria dinamica"); }

  Serial.println();
  Serial.printf("  Pilha: marca d'agua lida dentro de uma tarefa dedicada de %u bytes, antes e depois da operacao (64 B, 8 chamadas):\n",
                (unsigned) PROBE_TASK_STACK_BYTES);
  Serial.println("  (ESP-IDF devolve a marca em bytes; a marca inicial tem de ficar abaixo do tamanho da pilha)");

  for (size_t specIdx = 0; specIdx < 4; specIdx++) {
    if (!memoryStackProbe(specs[specIdx], 64, &stackProbe)) {
      reportProblem("a tarefa de medicao de pilha nao terminou");
      continue;
    }

    Serial.printf("      %s  marca inicial %u | marca final %u | consumo da operacao %d bytes\n",
                  specs[specIdx]->name, (unsigned) stackProbe.markStart, (unsigned) stackProbe.markEnd,
                  (int) stackProbe.markStart - (int) stackProbe.markEnd);
  }
}

// ---------------------------------------------------------------------------
// [3] Tempo do Ascon-128a
// ---------------------------------------------------------------------------

static void sectionAsconTiming()
{
  Serial.printf("[3] Tempo do Ascon-128a: %d execucoes por tamanho e operacao, %d medidas cada, interrupcoes ligadas\n", RUNS, ITERATIONS);
  Serial.println("    (cada '.' e uma execucao; a metrica entre execucoes e o piso de cada uma)");

  for (size_t index = 0; index < SIZE_COUNT; index++) {
    size_t length = payloadSizes[index];

    Serial.printf("  %2u B cifra   ", (unsigned) length);
    CrossRun encrypt = benchRepeat(&asconEncryptSpec, length, RUNS, ITERATIONS, false);

    Serial.printf("  %2u B decifra ", (unsigned) length);
    CrossRun decrypt = benchRepeat(&asconDecryptSpec, length, RUNS, ITERATIONS, false);

    CycleStats encryptIrqOff = benchMeasure(&asconEncryptSpec, length, ITERATIONS, true);

    asconEncryptFloor[index]       = encrypt.minFloor;
    asconDecryptFloor[index]       = decrypt.minFloor;
    asconEncryptFloorIrqOff[index] = encryptIrqOff.minCycles;

    reportCrossRunLine("cifra  ", &encrypt);
    reportCrossRunLine("decifra", &decrypt);
    Serial.printf("      cifra com interrupcoes desligadas, 1 execucao: piso %u | diferenca para o piso acima %d ciclos\n",
                  (unsigned) encryptIrqOff.minCycles, (int) encryptIrqOff.minCycles - (int) encrypt.minFloor);

    if (encrypt.runsAtFloor != RUNS || decrypt.runsAtFloor != RUNS) {
      reportNote("piso do Ascon nao reproduzido em todas as execucoes (ver [3])");
    }

    int irqDifference = (int) encryptIrqOff.minCycles - (int) encrypt.minFloor;
    if (irqDifference > FLOOR_MATCH_TOLERANCE || irqDifference < -FLOOR_MATCH_TOLERANCE) {
      reportNote("piso com e sem interrupcoes difere alem da tolerancia (ver [3])");
    }
  }

  if (asconDecryptFailures != 0) {
    reportProblem("decifragens do Ascon recusadas durante a medicao: o tempo de decifra nao vale");
  }

  // Modelo linear sobre as fronteiras de bloco.
  int i0 = sizeIndex(0), i2 = sizeIndex(2), i16 = sizeIndex(16), i23 = sizeIndex(23), i32 = sizeIndex(32), i64 = sizeIndex(64);

  if (i0 < 0 || i2 < 0 || i16 < 0 || i23 < 0 || i32 < 0 || i64 < 0) {
    reportNote("tamanhos padrao alterados: analise de modelo e granularidade omitida");
    return;
  }

  Serial.println();
  Serial.println("  Analise:");

  for (int operation = 0; operation < 2; operation++) {
    const uint32_t *floors = (operation == 0) ? asconEncryptFloor : asconDecryptFloor;
    const char     *label  = (operation == 0) ? "cifra  " : "decifra";

    double slope     = reportSlopePerBlock(floors[i16], floors[i64]);
    double intercept = (double) floors[i16] - slope;
    double linearity = reportLinearityPercent(floors[i16], floors[i32], floors[i64]);

    Serial.printf("      %s: parcela fixa extrapolada %.0f + %.1f ciclos por bloco de 16 B | desvio do ponto de 32 B: %.2f%%\n",
                  label, intercept, slope, linearity);
    Serial.printf("      %s: parcela fixa MEDIDA (0 B) %u ciclos | diferenca para a extrapolada %.0f ciclos\n",
                  label, (unsigned) floors[i0], (double) floors[i0] - intercept);

    if (linearity > LINEARITY_MAX_PERCENT) {
      reportNote("o custo do Ascon nao e linear nos blocos dentro da tolerancia (ver [3])");
    }
  }

  // Granularidade: o Ascon-128a executa uma permutacao por bloco COMPLETO
  // seguido de mais dados; o bloco final, cheio ou nao, e apenas preenchido,
  // byte a byte. Logo 2 B e 23 B nao pagam permutacao extra em relacao a 0 e
  // 16 B, mas pagam a copia dos bytes que sobram. O teste e: o degrau parcial
  // fica abaixo de um bloco inteiro.
  Serial.println("      Granularidade de bloco (esperado: 2 B e 23 B custam menos que um bloco a mais que 0 B e 16 B):");

  int step2  = (int) asconEncryptFloor[i2]  - (int) asconEncryptFloor[i0];
  int step23 = (int) asconEncryptFloor[i23] - (int) asconEncryptFloor[i16];
  int block  = (int) asconEncryptFloor[i32] - (int) asconEncryptFloor[i16];

  Serial.printf("      cifra: 2 B - 0 B = %d ciclos (%.0f por byte) | 23 B - 16 B = %d ciclos (%.0f por byte) | 32 B - 16 B = %d ciclos (um bloco)\n",
                step2, step2 / 2.0, step23, step23 / 7.0, block);

  if (step2 < 0 || step23 < 0 || step2 >= block || step23 >= block) {
    reportNote("o bloco parcial do Ascon custou um bloco inteiro ou mais (ver [3])");
  }
}

// ---------------------------------------------------------------------------
// [4] Tempo constante
// ---------------------------------------------------------------------------

static InputClass currentClass = CLASS_RAMP;

static void classPrepare(int iteration, size_t length)
{
  inputsPrepareClass(currentClass, iteration, length);
}

static void sectionConstantTime()
{
  Serial.printf("[4] Tempo constante do Ascon-128a: cifragem com interrupcoes desligadas, %d medidas por classe de entrada\n", ITERATIONS);

  static const size_t classSizes[] = { 16, 64 };

  for (size_t sizeIdx = 0; sizeIdx < 2; sizeIdx++) {
    size_t   length   = classSizes[sizeIdx];
    uint32_t minFloor = 0xFFFFFFFFu, maxFloor = 0;
    double   minMean  = 1.0e12, maxMean = 0.0;

    Serial.printf("  %2u B\n", (unsigned) length);

    for (int classIdx = 0; classIdx < CLASS_COUNT; classIdx++) {
      currentClass = (InputClass) classIdx;

      BenchSpec spec = asconEncryptSpec;
      spec.prepare = classPrepare;

      CycleStats stats = benchMeasure(&spec, length, ITERATIONS, true);
      reportStatsLine(inputsClassName(currentClass), &stats);

      if (stats.minCycles < minFloor) { minFloor = stats.minCycles; }
      if (stats.minCycles > maxFloor) { maxFloor = stats.minCycles; }
      if (stats.meanCycles < minMean) { minMean = stats.meanCycles; }
      if (stats.meanCycles > maxMean) { maxMean = stats.meanCycles; }

      delay(1);
    }

    Serial.printf("      entre classes: pisos de %u a %u (spread %u ciclos) | medias de %.2f a %.2f (spread %.2f ciclos, %.4f%% da media)\n",
                  (unsigned) minFloor, (unsigned) maxFloor, (unsigned) (maxFloor - minFloor),
                  minMean, maxMean, maxMean - minMean, 100.0 * (maxMean - minMean) / minMean);

    if (maxFloor - minFloor > CLASS_MATCH_TOLERANCE || maxMean - minMean > (double) CLASS_MATCH_TOLERANCE) {
      reportNote("o tempo de cifragem variou entre classes de entrada alem da tolerancia (ver [4])");
    }
  }

  currentClass = CLASS_RAMP;
}

// ---------------------------------------------------------------------------
// [5] Comparativo com AES-128-GCM
// ---------------------------------------------------------------------------

struct Comparison {
  CrossRun ascon;
  CrossRun aes;
  double   minRatio;
  double   maxRatio;
  double   sumRatios;
  int      runsAsconFaster;
};

// Os dois algoritmos medidos alternadamente na mesma execucao, para que a
// razao de cada execucao compare pisos obtidos nas mesmas condicoes.
static Comparison compareRepeat(const BenchSpec *asconSpec, const BenchSpec *aesSpec, size_t length)
{
  Comparison comparison;
  benchCrossRunInit(&comparison.ascon, RUNS);
  benchCrossRunInit(&comparison.aes,   RUNS);

  comparison.minRatio        = 1.0e9;
  comparison.maxRatio        = 0.0;
  comparison.sumRatios       = 0.0;
  comparison.runsAsconFaster = 0;

  for (int run = 0; run < RUNS; run++) {
    CycleStats asconStats = benchMeasure(asconSpec, length, ITERATIONS, false);
    CycleStats aesStats   = benchMeasure(aesSpec,   length, ITERATIONS, false);

    benchCrossRunAdd(&comparison.ascon, &asconStats);
    benchCrossRunAdd(&comparison.aes,   &aesStats);

    // Piso zero nao acontece na placa; a guarda so evita divisao por zero.
    double ratio = asconStats.minCycles > 0 ? (double) aesStats.minCycles / (double) asconStats.minCycles : 0.0;

    if (ratio < comparison.minRatio) { comparison.minRatio = ratio; }
    if (ratio > comparison.maxRatio) { comparison.maxRatio = ratio; }
    comparison.sumRatios += ratio;

    if (asconStats.minCycles < aesStats.minCycles) { comparison.runsAsconFaster++; }

    Serial.print('.');
    delay(1);
  }

  Serial.println();
  return comparison;
}

static void printComparison(const Comparison *comparison)
{
  reportCrossRunLine("Ascon-128a ", &comparison->ascon);
  reportCrossRunLine("AES-128-GCM", &comparison->aes);
  Serial.printf("      razao AES/Ascon: min %.3f | max %.3f | media %.3f | Ascon mais rapido em %d/%d execucoes\n",
                comparison->minRatio, comparison->maxRatio, comparison->sumRatios / RUNS,
                comparison->runsAsconFaster, RUNS);
}

static void sectionComparison()
{
  Serial.printf("[5] Comparativo Ascon-128a (software) x AES-128-GCM (mbedTLS): %d execucoes por tamanho e operacao, alternadas\n", RUNS);
  Serial.println("    (interrupcoes ligadas nos dois; piso de cada execucao)");

  int totalAsconFaster = 0;

  for (size_t index = 0; index < SIZE_COUNT; index++) {
    size_t length = payloadSizes[index];

    Serial.printf("  %2u B cifra   ", (unsigned) length);
    Comparison encrypt = compareRepeat(&asconEncryptSpec, &aesGcmEncryptSpec, length);

    Serial.printf("  %2u B decifra ", (unsigned) length);
    Comparison decrypt = compareRepeat(&asconDecryptSpec, &aesGcmDecryptSpec, length);

    gcmEncryptFloor[index] = encrypt.aes.minFloor;
    gcmDecryptFloor[index] = decrypt.aes.minFloor;

    Serial.printf("      cifra:\n");
    printComparison(&encrypt);
    Serial.printf("      decifra:\n");
    printComparison(&decrypt);

    totalAsconFaster += encrypt.runsAsconFaster + decrypt.runsAsconFaster;

    if (encrypt.aes.runsAtFloor != RUNS || decrypt.aes.runsAtFloor != RUNS) {
      reportNote("piso do AES-GCM nao reproduzido em todas as execucoes (ver [5])");
    }
  }

  int totalRuns = 2 * RUNS * (int) SIZE_COUNT;
  Serial.printf("  Ascon mais rapido que o AES-GCM em %d/%d execucoes (todos os tamanhos, cifra e decifra)\n",
                totalAsconFaster, totalRuns);

  if (totalAsconFaster != totalRuns) {
    reportNote("houve execucoes em que o AES-GCM foi mais rapido (ver [5])");
  }

  if (aesApiError)               { reportProblem("o mbedTLS devolveu erro em alguma medicao: os tempos do AES nao valem"); }
  if (aesDecryptFailures != 0)   { reportProblem("decifragens do AES-GCM recusadas durante a medicao: o tempo de decifra nao vale"); }
  if (asconDecryptFailures != 0) { reportProblem("decifragens do Ascon recusadas durante o comparativo"); }

  // Granularidade do AES-GCM, para contraste com a do Ascon: o CTR cifra
  // ceil(n/16) blocos e o GHASH processa os mesmos blocos mais um de tamanho.
  int i0 = sizeIndex(0), i2 = sizeIndex(2), i16 = sizeIndex(16), i23 = sizeIndex(23), i32 = sizeIndex(32);

  if (i0 >= 0 && i2 >= 0 && i16 >= 0 && i23 >= 0 && i32 >= 0) {
    Serial.println("      Granularidade do AES-GCM (esperado: 2 B ~ 16 B e 23 B ~ 32 B, pois o CTR cifra blocos inteiros):");
    Serial.printf("      cifra: 2 B - 0 B = %d | 16 B - 2 B = %d | 23 B - 16 B = %d | 32 B - 23 B = %d ciclos\n",
                  (int) gcmEncryptFloor[i2] - (int) gcmEncryptFloor[i0],
                  (int) gcmEncryptFloor[i16] - (int) gcmEncryptFloor[i2],
                  (int) gcmEncryptFloor[i23] - (int) gcmEncryptFloor[i16],
                  (int) gcmEncryptFloor[i32] - (int) gcmEncryptFloor[i23]);
  }
}

// ---------------------------------------------------------------------------
// [6] Decomposicao: o AES-GCM e acelerado por hardware neste chip?
// ---------------------------------------------------------------------------

static void printPath(const char *label, uint32_t floor16, uint32_t floor32, uint32_t floor64)
{
  Serial.printf("  %s: 16 B %5u | 32 B %5u | 64 B %5u | por bloco %7.1f ciclos | linearidade %.2f%%\n",
                label, (unsigned) floor16, (unsigned) floor32, (unsigned) floor64,
                reportSlopePerBlock(floor16, floor64),
                reportLinearityPercent(floor16, floor32, floor64));
}

static void sectionDecomposition()
{
  Serial.println("[6] O AES-GCM e acelerado por hardware neste chip?");
  Serial.println("  [6a] O que o SDK declara (tempo de compilacao)");
  aesReportBuildCapabilities();

  int i16 = sizeIndex(16), i32 = sizeIndex(32), i64 = sizeIndex(64);

  if (i16 < 0 || i32 < 0 || i64 < 0) {
    reportNote("tamanhos padrao alterados: decomposicao omitida");
    return;
  }

  Serial.println();
  Serial.printf("  [6b] Evidencia empirica: custo marginal por bloco de 16 B, pisos de %d execucoes\n", RUNS);

  uint32_t ctrFloor[3];
  const size_t sizes[3] = { 16, 32, 64 };

  for (int index = 0; index < 3; index++) {
    Serial.printf("  %2u B CTR ", (unsigned) sizes[index]);
    CrossRun ctr = benchRepeat(&aesCtrSpec, sizes[index], RUNS, ITERATIONS, false);
    ctrFloor[index] = ctr.minFloor;
  }

  Serial.println();
  printPath("AES-CTR (so cifra AES) ", ctrFloor[0], ctrFloor[1], ctrFloor[2]);
  printPath("AES-GCM (cifra + GHASH)", gcmEncryptFloor[i16], gcmEncryptFloor[i32], gcmEncryptFloor[i64]);
  printPath("Ascon-128a (software)  ", asconEncryptFloor[i16], asconEncryptFloor[i32], asconEncryptFloor[i64]);

  double ctrPerBlock   = reportSlopePerBlock(ctrFloor[0], ctrFloor[2]);
  double gcmPerBlock   = reportSlopePerBlock(gcmEncryptFloor[i16], gcmEncryptFloor[i64]);
  double asconPerBlock = reportSlopePerBlock(asconEncryptFloor[i16], asconEncryptFloor[i64]);
  double ghashPerBlock = gcmPerBlock - ctrPerBlock;

  double worstLinearity = reportLinearityPercent(ctrFloor[0], ctrFloor[1], ctrFloor[2]);
  double gcmLinearity   = reportLinearityPercent(gcmEncryptFloor[i16], gcmEncryptFloor[i32], gcmEncryptFloor[i64]);
  if (gcmLinearity > worstLinearity) { worstLinearity = gcmLinearity; }

  Serial.println();
  Serial.println("  Derivacoes (a subtracao GCM - CTR e exata: esp_aes_gcm.c chama esp_aes_crypt_ctr):");
  Serial.printf("      GHASH por bloco (GCM - CTR)               : %.1f ciclos (%.2f us)\n", ghashPerBlock, benchCyclesToMicroseconds(ghashPerBlock));
  Serial.printf("      Ascon-128a completo por bloco             : %.1f ciclos\n", asconPerBlock);
  if (ctrPerBlock > 0.0) {
    Serial.printf("      GHASH / cifra AES                         : %.2fx\n", ghashPerBlock / ctrPerBlock);
    Serial.printf("      cifra AES medida / nucleo do TRM do ESP32 (%d): %.0fx\n", TRM_BLOCK_CYCLES_MAX, ctrPerBlock / TRM_BLOCK_CYCLES_MAX);
  }

  Serial.println();
  Serial.println("  Conclusao:");

  if (worstLinearity > LINEARITY_MAX_PERCENT) {
    Serial.printf("      o ponto de 32 B desvia %.2f%% da reta 16->64 B: o modelo linear nao vale e a subtracao nao isola o GHASH.\n", worstLinearity);
    reportNote("decomposicao GCM - CTR sem modelo linear valido (ver [6])");
    return;
  }

  Serial.printf("      modelo linear valido (desvio maximo em 32 B: %.2f%%).\n", worstLinearity);

  if (ghashPerBlock < 0.0) {
    Serial.println("      GHASH negativo: o CTR saiu mais caro que o GCM, o que e impossivel se o GCM contem o CTR.");
    reportProblem("decomposicao inconsistente: GHASH negativo (ver [6])");
  }
  else if (ghashPerBlock <= 10.0 * TRM_BLOCK_CYCLES_MAX) {
    Serial.printf("      o GHASH custa %.0f ciclos por bloco, da ordem do proprio bloco AES: compativel com autenticacao em HARDWARE.\n", ghashPerBlock);
    reportNote("o GHASH parece acelerado por hardware neste chip; o texto da Secao 5.2.4 precisa ser revisto");
  }
  else {
    Serial.printf("      o GHASH custa %.0f ciclos por bloco, %.0fx o nucleo do bloco AES: multiplicacao em GF(2^128) na CPU, ou seja, SOFTWARE.\n",
                  ghashPerBlock, ghashPerBlock / TRM_BLOCK_CYCLES_MAX);
    Serial.println("      => o GCM NAO e totalmente acelerado por hardware aqui.");
  }
}

// ---------------------------------------------------------------------------
// [7] Resumo
// ---------------------------------------------------------------------------

static void sectionSummary()
{
  Serial.println("[7] Resumo");

  int i23 = sizeIndex(23), i16 = sizeIndex(16), i64 = sizeIndex(64);

  if (i23 >= 0 && i16 >= 0 && i64 >= 0) {
    Serial.printf("  Mensagem tipica de 23 B (dataset Tour Perret): Ascon cifra %u ciclos (%.2f us) | AES-GCM cifra %u ciclos (%.2f us) | razao %.2f\n",
                  (unsigned) asconEncryptFloor[i23], benchCyclesToMicroseconds(asconEncryptFloor[i23]),
                  (unsigned) gcmEncryptFloor[i23],   benchCyclesToMicroseconds(gcmEncryptFloor[i23]),
                  asconEncryptFloor[i23] > 0 ? (double) gcmEncryptFloor[i23] / (double) asconEncryptFloor[i23] : 0.0);
    Serial.printf("  Custo por bloco de 16 B: Ascon %.1f | AES-GCM %.1f ciclos\n",
                  reportSlopePerBlock(asconEncryptFloor[i16], asconEncryptFloor[i64]),
                  reportSlopePerBlock(gcmEncryptFloor[i16],   gcmEncryptFloor[i64]));
  }

  Serial.printf("  Problemas: %d | Ressalvas: %d\n", reportProblemCount(), reportNoteCount());
  Serial.println();

  if (reportProblemCount() == 0) {
    Serial.println(">>> BENCHMARK OK: autoteste, memoria, tempo, comparativo e decomposicao sem problemas <<<");
    if (reportNoteCount() > 0) {
      Serial.println(">>> ha ressalvas acima (linhas 'RESSALVA'); o texto precisa mencionar cada uma <<<");
    }
  }
  else {
    Serial.println(">>> BENCHMARK COM PROBLEMAS: ver as linhas 'PROBLEMA' acima; os numeros afetados nao valem <<<");
  }
}

// ---------------------------------------------------------------------------

void benchSuiteRun()
{
  Serial.println();
  Serial.println("=== Ascon-128a no ESP32: memoria, tempo e comparativo com AES-128-GCM (Secoes 3.4.3, 5.2.3 e 5.2.4) ===");
  Serial.println();

  boardReport();
  printSeparator();

  if (!sectionSelfCheck()) {
    printSeparator();
    Serial.println(">>> AUTOTESTE FALHOU: nada foi medido <<<");
    return;
  }

  printSeparator();
  sectionMemory();
  printSeparator();
  sectionAsconTiming();
  printSeparator();
  sectionConstantTime();
  printSeparator();
  sectionComparison();
  printSeparator();
  sectionDecomposition();
  printSeparator();
  sectionSummary();
}
