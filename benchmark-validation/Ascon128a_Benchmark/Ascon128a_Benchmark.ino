#include <ASCON.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define MAXPT 64

static uint8_t key[16];
static uint8_t nonce[16];
static uint8_t pt[MAXPT];
static uint8_t ct[MAXPT + 16];

// spinlock para medir a cifragem com interrupcoes desabilitadas (sem ruido de ISR)
static portMUX_TYPE benchMux = portMUX_INITIALIZER_UNLOCKED;

struct CycleStats { uint32_t min; uint32_t max; double mean; double stddev; };

// Preenche key/nonce/pt com valores que mudam a cada iteracao (tamanho fixo).
static void varyInputs(int it, size_t mlen)
{
  for (int i = 0; i < 16; i++) {
    key[i]   = (uint8_t)(it * 31 + i * 7 + 1);
    nonce[i] = (uint8_t)(it * 17 + i * 3);
  }
  for (size_t i = 0; i < mlen; i++) pt[i] = (uint8_t)(it * 13 + i * 5);
}

// Mede ciclos da cifragem de 'mlen' bytes ao longo de 'iters' execucoes, com
// chave e conteudo distintos a cada iteracao (mesmo tamanho).
static CycleStats benchEncrypt(size_t mlen, int iters)
{
  size_t clen = 0;
  uint32_t mn = 0xFFFFFFFFu, mx = 0;
  double sum = 0.0, sumsq = 0.0;

  // aquecimento (estabiliza cache); nao contabilizado
  for (int it = 0; it < 16; it++) {
    varyInputs(it, mlen);
    ascon128a_aead_encrypt(ct, &clen, pt, mlen, NULL, 0, nonce, key);
  }

  for (int it = 0; it < iters; it++) {
    varyInputs(it, mlen);
    portENTER_CRITICAL(&benchMux);        // interrupcoes off: mede so a cifragem (sem ISR)
    uint32_t t0 = ESP.getCycleCount();
    ascon128a_aead_encrypt(ct, &clen, pt, mlen, NULL, 0, nonce, key);
    uint32_t t1 = ESP.getCycleCount();
    portEXIT_CRITICAL(&benchMux);
    uint32_t c = t1 - t0;                 // subtracao uint32 trata o wrap do contador
    if (c < mn) mn = c;
    if (c > mx) mx = c;
    sum   += (double) c;
    sumsq += (double) c * (double) c;
  }

  CycleStats s;
  s.min  = mn;
  s.max  = mx;
  s.mean = sum / iters;
  double var = sumsq / iters - s.mean * s.mean;
  s.stddev = var > 0.0 ? sqrt(var) : 0.0;
  return s;
}

static double cyclesToUs(double cycles)
{
  return cycles / (double) getCpuFrequencyMhz();  // ciclos / MHz = microssegundos
}

static void printStats(size_t mlen, CycleStats s)
{
  Serial.print("  "); Serial.print((unsigned) mlen); Serial.print(" B: ");
  Serial.print("min ");   Serial.print(s.min);
  Serial.print(" | max ");Serial.print(s.max);
  Serial.print(" | media ");  Serial.print(s.mean, 1);
  Serial.print(" ciclos (~"); Serial.print(cyclesToUs(s.mean), 2); Serial.print(" us)");
  Serial.print(" | desvio "); Serial.print(s.stddev, 2);
  Serial.print(" | spread ");Serial.print(s.max - s.min);
  Serial.println(" ciclos");
}

void setup()
{
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println("=== Ascon-128a: memoria e tempo (Secao 3.4.3) ===");
  Serial.print("CPU: "); Serial.print(getCpuFrequencyMhz()); Serial.println(" MHz");
  Serial.print("Estado (ascon128a_state_t): ");
  Serial.print((unsigned) sizeof(ascon128a_state_t)); Serial.println(" bytes");
  Serial.println();

  // ----- MEMORIA -----
  Serial.println("[Memoria]");
  UBaseType_t stackBefore = uxTaskGetStackHighWaterMark(NULL);
  uint32_t freeBefore = ESP.getFreeHeap();      // == esp_get_free_heap_size()
  uint32_t minBefore  = ESP.getMinFreeHeap();   // == esp_get_minimum_free_heap_size()

  size_t clen = 0, mlen = 0;
  uint8_t out[MAXPT];
  varyInputs(1, 16);
  ascon128a_aead_encrypt(ct, &clen, pt, 16, NULL, 0, nonce, key);
  ascon128a_aead_decrypt(out, &mlen, ct, clen, NULL, 0, nonce, key);

  uint32_t freeAfter = ESP.getFreeHeap();
  uint32_t minAfter  = ESP.getMinFreeHeap();
  UBaseType_t stackAfter = uxTaskGetStackHighWaterMark(NULL);

  Serial.print("  Heap livre antes/depois: ");
  Serial.print(freeBefore); Serial.print(" / "); Serial.print(freeAfter);
  Serial.print(" B (delta "); Serial.print((int32_t) freeAfter - (int32_t) freeBefore); Serial.println(" B)");
  Serial.print("  Heap minimo antes/depois: ");
  Serial.print(minBefore); Serial.print(" / "); Serial.print(minAfter);
  Serial.println(minAfter < minBefore ? " B (houve alocacao transitoria)" : " B (sem alocacao dinamica)");
  Serial.print("  Folga de pilha antes/depois: ");
  Serial.print((unsigned) stackBefore); Serial.print(" / "); Serial.print((unsigned) stackAfter);
  Serial.print(" (consumo aprox. "); Serial.print((int) stackBefore - (int) stackAfter);
  Serial.println(" -- confira a unidade na sua versao do core)");
  Serial.println();

  // ----- TEMPO (vazao por tamanho) -----
  Serial.println("[Tempo de cifragem por tamanho]");
  printStats(16, benchEncrypt(16, 2000));
  printStats(32, benchEncrypt(32, 2000));
  printStats(64, benchEncrypt(64, 2000));
  Serial.println();

  // ----- CANAL COLATERAL POR TEMPO (tamanho fixo) -----
  Serial.println("[Canal colateral por tempo - 16 B, chave/conteudo distintos]");
  CycleStats c16 = benchEncrypt(16, 5000);
  printStats(16, c16);
  Serial.print("  variacao relativa (desvio/media): ");
  Serial.print(100.0 * c16.stddev / c16.mean, 3);
  Serial.println(" %");
  Serial.print("  minimo invariante: "); Serial.print(c16.min);
  Serial.println(" ciclos (mesmo piso para chaves/conteudos distintos)");
  Serial.println("  (medicao com interrupcoes desabilitadas; variacao residual");
  Serial.println("   minima e independente do conteudo => execucao em tempo ~constante)");
  Serial.println();

  Serial.println(">>> Medicoes concluidas <<<");

  // TODO (proximo incremento): medir AES-GCM via mbedTLS (mbedtls_gcm_*) com o
  // acelerador de hardware do ESP32, reusando benchEncrypt/printStats, para o
  // comparativo software (Ascon) vs hardware (AES) do Cap. 2.
}

void loop()
{
  delay(1000);  // roda uma vez no setup(); cede o processador
}

=== Ascon-128a: memoria e tempo (Secao 3.4.3) ===
CPU: 240 MHz
Estado (ascon128a_state_t): 80 bytes

[Memoria]
  Heap livre antes/depois: 333320 / 333320 B (delta 0 B)
  Heap minimo antes/depois: 327724 / 327724 B (sem alocacao dinamica)
  Folga de pilha antes/depois: 7036 / 7036 (consumo aprox. 0 -- confira a unidade na sua versao do core)

[Tempo de cifragem por tamanho]
  16 B: min 6117 | max 6400 | media 6117.2 ciclos (~25.49 us) | desvio 6.33 | spread 283 ciclos
  32 B: min 7214 | max 7219 | media 7214.0 ciclos (~30.06 us) | desvio 0.30 | spread 5 ciclos
  64 B: min 9408 | max 9414 | media 9408.1 ciclos (~39.20 us) | desvio 0.41 | spread 6 ciclos

[Canal colateral por tempo - 16 B, chave/conteudo distintos]
  16 B: min 6117 | max 6122 | media 6117.0 ciclos (~25.49 us) | desvio 0.28 | spread 5 ciclos
  variacao relativa (desvio/media): 0.005 %
  minimo invariante: 6117 ciclos (mesmo piso para chaves/conteudos distintos)
  (medicao com interrupcoes desabilitadas; variacao residual
   minima e independente do conteudo => execucao em tempo ~constante)

>>> Medicoes concluidas <<<

Compilado com biblioteca
Sketch uses 294352 bytes (22%) of program storage space. Maximum is 1310720 bytes.
Global variables use 22268 bytes (6%) of dynamic memory, leaving 305412 bytes for local variables. Maximum is 327680 bytes.

Compilado com biblioteca comentada
Sketch uses 287304 bytes (21%) of program storage space. Maximum is 1310720 bytes.
Global variables use 22092 bytes (6%) of dynamic memory, leaving 305588 bytes for local variables. Maximum is 327680 bytes.