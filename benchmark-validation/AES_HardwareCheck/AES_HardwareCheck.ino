/*
 * AES_HardwareCheck -- verificacao da afirmacao "no ESP32 classico o AES-GCM nao
 * e totalmente acelerado por hardware: so o bloco AES roda no periferico; o GHASH
 * roda em software".
 *
 * Essa afirmacao sustenta a interpretacao do comparativo da Secao 5.2.4, entao
 * convem comprova-la na propria placa, e nao apenas cita-la. O sketch ataca a
 * questao por dois caminhos independentes:
 *
 *   (1) CAPACIDADE DECLARADA (tempo de compilacao). Le as macros do proprio SDK
 *       usado para compilar ESTE firmware e reconstroi, a partir delas, qual
 *       caminho de codigo o AES-GCM realmente toma. Cada macro e reportada em
 *       TRES estados -- DEFINIDA com valor, DEFINIDA sem valor, e AUSENTE --
 *       porque uma macro ausente so e evidencia se o cabecalho que a definiria
 *       foi de fato alcancado. Sem essa distincao, "ausente" pode significar
 *       "recurso inexistente" ou "cabecalho nao incluido", que sao conclusoes
 *       opostas.
 *
 *   (2) EVIDENCIA EMPIRICA (tempo de execucao). Mede o custo MARGINAL por bloco
 *       de 16 B de quatro caminhos, na mesma placa:
 *           AES-ECB  = cifra AES chamada um bloco por vez pela API publica
 *           AES-CTR  = cifra AES em fluxo, uma aquisicao do periferico por chamada
 *           AES-GCM  = a mesma cifra AES em fluxo + o GHASH (autenticacao)
 *           Ascon    = referencia em software puro
 *       A diferenca (GCM - CTR) isola o custo do GHASH por bloco.
 *       A diferenca (ECB - CTR) isola o custo da camada de port do ESP-IDF
 *       (spinlock + liga/desliga do periferico + reescrita da chave) que e paga
 *       uma vez por CHAMADA no CTR e uma vez por BLOCO no ECB.
 *
 * Usa-se o custo MARGINAL (inclinacao entre 16/32/64 B), e nao o total, porque
 * assim se cancela a parcela fixa de cada API (aquisicao do periferico, setkey,
 * chamada), isolando o que de fato acontece por bloco de dados. A linearidade
 * dessa inclinacao e verificada explicitamente com o ponto intermediario de 32 B:
 * se o modelo linear nao descrever os dados, a subtracao nao tem sentido.
 *
 * Metodologia de tempo identica a da Secao 3.4.3: minimo de ciclos (piso livre
 * de interrupcao). Nao se desabilitam interrupcoes porque o driver de AES por
 * hardware entra em secao critica por conta propria (portENTER_CRITICAL sobre um
 * spinlock), e aninhar isso a partir do sketch e proibido.
 *
 * REFERENCIAS DE CODIGO-FONTE (ESP-IDF), para conferencia:
 *   components/mbedtls/port/aes/block/esp_aes.c   -- esp_aes_block, esp_aes_crypt_ctr
 *   components/mbedtls/port/aes/esp_aes_gcm.c     -- esp_gcm_ghash, gcm_mult
 *   components/mbedtls/port/include/mbedtls/esp_config.h -- define MBEDTLS_GCM_ALT
 *   components/mbedtls/Kconfig                    -- MBEDTLS_HARDWARE_GCM
 *   components/soc/<chip>/include/soc/soc_caps.h  -- SOC_AES_SUPPORT_GCM/DMA
 */

#include <ASCON.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include <string.h>

/* Cabecalhos opcionais. Testa-se a presenca antes de incluir para nao confundir
 * "macro ausente" com "cabecalho ausente" -- um falso negativo arruinaria o
 * item [1]. As flags abaixo registram o que foi realmente alcancado. */
#if defined(__has_include)
#  if __has_include("soc/soc_caps.h")
#    include "soc/soc_caps.h"
#    define SOC_CAPS_HEADER_REACHED 1
#  endif
#  if __has_include("esp_idf_version.h")
#    include "esp_idf_version.h"
#    define IDF_VERSION_HEADER_REACHED 1
#  endif
#endif

#ifdef SOC_CAPS_HEADER_REACHED
static const bool socCapsReached = true;
#else
static const bool socCapsReached = false;
#endif

/* MBEDTLS_GCM_C so existe se o cabecalho de configuracao do mbedTLS (esp_config.h)
 * foi alcancado por mbedtls/gcm.h. Serve de sentinela: sem ele, a ausencia de
 * MBEDTLS_GCM_ALT nao prova nada. */
#ifdef MBEDTLS_GCM_C
static const bool mbedtlsConfigReached = true;
#else
static const bool mbedtlsConfigReached = false;
#endif

#define MAX_PLAINTEXT 64
#define AES_BLOCK_BYTES 16
#define ITERATIONS 2000
#define WARMUP_ITERATIONS 16

/* Custo do nucleo do acelerador por bloco, segundo o manual do fabricante:
 * ESP32 Technical Reference Manual v5.8, secao 14.3.5 "Speed" (p. 284):
 *   "The AES Accelerator requires 11 to 15 clock cycles to encrypt a message
 *    block, and 21 or 22 clock cycles to decrypt a message block."
 * Prefere-se essa fonte ao comentario de esp_aes.c, que cita 208 ciclos junto
 * de "+600 cycles for DPORT protection" -- mecanismo posteriormente alterado,
 * o que deixa o numero sem data. Serve de regua: um GHASH em hardware custaria
 * a mesma ordem de grandeza que um bloco. */
#define TRM_BLOCK_CYCLES_MAX 15

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t initializationVector[12];
static uint8_t plaintext[MAX_PLAINTEXT];
static uint8_t ciphertext[MAX_PLAINTEXT + ASCON128_TAG_SIZE];
static uint8_t aesCiphertext[MAX_PLAINTEXT];
static uint8_t aesTag[16];

static bool measurementFailed = false;

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

// ---------------------------------------------------------------------------
// Relato de macros em tres estados
// ---------------------------------------------------------------------------

static void printMacroName(const char *name)
{
  Serial.print("  ");
  Serial.print(name);

  for (size_t padding = strlen(name); padding < 30; padding++) {
    Serial.print(' ');
  }

  Serial.print(": ");
}

static void printMacroNote(const char *note)
{
  if (note != NULL) {
    Serial.print("   <- ");
    Serial.print(note);
  }

  Serial.println();
}

/* Macro definida COM valor numerico (ex.: SOC_AES_SUPPORT_GCM = 1).
 * Reporta o valor porque "definida com valor 0" e um estado real e distinto
 * de "definida com valor 1". */
static void reportMacroValue(const char *name, long value, const char *note)
{
  printMacroName(name);
  Serial.print("DEFINIDA (valor ");
  Serial.print(value);
  Serial.print(")");
  printMacroNote(note);
}

/* Macro definida SEM valor (ex.: MBEDTLS_GCM_ALT). */
static void reportMacroFlag(const char *name, const char *note)
{
  printMacroName(name);
  Serial.print("DEFINIDA (sem valor)");
  printMacroNote(note);
}

/* Macro ausente. So e evidencia se o cabecalho que a definiria foi alcancado. */
static void reportMacroAbsent(const char *name, bool definingHeaderReached, const char *note)
{
  printMacroName(name);

  if (definingHeaderReached) {
    Serial.print("AUSENTE");
    printMacroNote(note);
  }
  else {
    Serial.print("AUSENTE -- INCONCLUSIVO");
    printMacroNote("cabecalho que a definiria nao foi alcancado; nao conclua nada");
  }
}

// ---------------------------------------------------------------------------
// Caminhos medidos
// ---------------------------------------------------------------------------

// ----- Ascon-128a: referencia em software puro -----
static uint32_t floorAscon(size_t messageLength, int iterations)
{
  size_t ciphertextLength = 0;
  uint32_t minCycles = 0xFFFFFFFFu;

  for (int iteration = 0; iteration < WARMUP_ITERATIONS; iteration++) {
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
  }

  return minCycles;
}

/* ----- AES-ECB chamado um bloco por vez -----
 * Cada chamada a mbedtls_aes_crypt_ecb paga, no port do ESP-IDF, uma aquisicao
 * completa do periferico: portENTER_CRITICAL sobre o spinlock do AES,
 * periph_module_enable, reescrita da chave, a operacao de bloco,
 * periph_module_disable e portEXIT_CRITICAL. Medir este caminho quantifica
 * essa sobrecarga de port, que no CTR e paga uma unica vez por chamada. */
static uint32_t floorAesEcbPerBlock(size_t messageLength, int iterations)
{
  mbedtls_aes_context aesContext;
  mbedtls_aes_init(&aesContext);

  if (mbedtls_aes_setkey_enc(&aesContext, key, 128) != 0) {
    Serial.println("  ERRO: mbedtls_aes_setkey_enc falhou (ECB)");
    measurementFailed = true;
    mbedtls_aes_free(&aesContext);
    return 0;
  }

  size_t blockCount = messageLength / AES_BLOCK_BYTES;
  uint32_t minCycles = 0xFFFFFFFFu;

  for (int iteration = 0; iteration < iterations + WARMUP_ITERATIONS; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();

    for (size_t block = 0; block < blockCount; block++) {
      mbedtls_aes_crypt_ecb(&aesContext, MBEDTLS_AES_ENCRYPT,
                            plaintext + block * AES_BLOCK_BYTES,
                            aesCiphertext + block * AES_BLOCK_BYTES);
    }

    uint32_t endCycles = ESP.getCycleCount();
    uint32_t cycles = endCycles - startCycles;

    if (iteration >= WARMUP_ITERATIONS && cycles < minCycles) {
      minCycles = cycles;
    }
  }

  mbedtls_aes_free(&aesContext);
  return minCycles;
}

// ----- AES-CTR: SO a cifra AES (acelerador), sem autenticacao -----
static uint32_t floorAesCtr(size_t messageLength, int iterations)
{
  mbedtls_aes_context aesContext;
  mbedtls_aes_init(&aesContext);

  if (mbedtls_aes_setkey_enc(&aesContext, key, 128) != 0) {
    Serial.println("  ERRO: mbedtls_aes_setkey_enc falhou (CTR)");
    measurementFailed = true;
    mbedtls_aes_free(&aesContext);
    return 0;
  }

  uint32_t minCycles = 0xFFFFFFFFu;

  for (int iteration = 0; iteration < iterations + WARMUP_ITERATIONS; iteration++) {
    varyInputs(iteration, messageLength);

    // preparacao fora da regiao medida
    uint8_t nonceCounter[16];
    uint8_t streamBlock[16];
    size_t  nonceOffset = 0;

    memcpy(nonceCounter, initializationVector, 12);
    memset(nonceCounter + 12, 0, 4);
    memset(streamBlock, 0, sizeof(streamBlock));

    uint32_t startCycles = ESP.getCycleCount();
    int status = mbedtls_aes_crypt_ctr(&aesContext, messageLength, &nonceOffset,
                                       nonceCounter, streamBlock, plaintext, aesCiphertext);
    uint32_t endCycles = ESP.getCycleCount();

    if (status != 0) {
      Serial.println("  ERRO: mbedtls_aes_crypt_ctr retornou erro");
      measurementFailed = true;
      mbedtls_aes_free(&aesContext);
      return 0;
    }

    uint32_t cycles = endCycles - startCycles;

    if (iteration >= WARMUP_ITERATIONS && cycles < minCycles) {
      minCycles = cycles;
    }
  }

  mbedtls_aes_free(&aesContext);
  return minCycles;
}

// ----- AES-GCM: a cifra AES + o GHASH -----
static uint32_t floorAesGcm(size_t messageLength, int iterations)
{
  mbedtls_gcm_context gcmContext;
  mbedtls_gcm_init(&gcmContext);

  if (mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
    Serial.println("  ERRO: mbedtls_gcm_setkey falhou");
    measurementFailed = true;
    mbedtls_gcm_free(&gcmContext);
    return 0;
  }

  uint32_t minCycles = 0xFFFFFFFFu;

  for (int iteration = 0; iteration < iterations + WARMUP_ITERATIONS; iteration++) {
    varyInputs(iteration, messageLength);

    uint32_t startCycles = ESP.getCycleCount();
    int status = mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, messageLength,
                                           initializationVector, 12, NULL, 0,
                                           plaintext, aesCiphertext, 16, aesTag);
    uint32_t endCycles = ESP.getCycleCount();

    if (status != 0) {
      Serial.println("  ERRO: mbedtls_gcm_crypt_and_tag retornou erro");
      measurementFailed = true;
      mbedtls_gcm_free(&gcmContext);
      return 0;
    }

    uint32_t cycles = endCycles - startCycles;

    if (iteration >= WARMUP_ITERATIONS && cycles < minCycles) {
      minCycles = cycles;
    }
  }

  mbedtls_gcm_free(&gcmContext);
  return minCycles;
}

// ---------------------------------------------------------------------------
// Analise
// ---------------------------------------------------------------------------

/* Custo marginal por bloco de 16 B, a partir dos pisos de 16 e 64 B.
 * Usa (64B - 16B)/3 por ser a estimativa com maior alavancagem (3 blocos). */
static double marginalPerBlock(uint32_t floor16, uint32_t floor64)
{
  return ((double) floor64 - (double) floor16) / 3.0;
}

/* Verifica se o ponto intermediario de 32 B cai sobre a reta definida pelos
 * pontos de 16 e 64 B. Se nao cair, o modelo linear nao vale e a subtracao
 * (GCM - CTR) nao isola o GHASH. Retorna o desvio relativo em porcento. */
static double linearityDivergencePercent(uint32_t floor16, uint32_t floor32, uint32_t floor64)
{
  double predicted32 = (double) floor16 + marginalPerBlock(floor16, floor64);

  if (predicted32 == 0.0) {
    return 0.0;
  }

  double difference = (double) floor32 - predicted32;

  if (difference < 0.0) {
    difference = -difference;
  }

  return 100.0 * difference / predicted32;
}

static void printPath(const char *label, uint32_t floor16, uint32_t floor32, uint32_t floor64)
{
  Serial.print("  ");
  Serial.print(label);
  Serial.print(": 16 B ");
  Serial.print(floor16);
  Serial.print(" | 32 B ");
  Serial.print(floor32);
  Serial.print(" | 64 B ");
  Serial.print(floor64);
  Serial.print(" | por bloco ");
  Serial.print(marginalPerBlock(floor16, floor64), 1);
  Serial.print(" ciclos | linearidade ");
  Serial.print(linearityDivergencePercent(floor16, floor32, floor64), 2);
  Serial.println("%");
}

// ---------------------------------------------------------------------------
// Item [1]: capacidade declarada pelo SDK
// ---------------------------------------------------------------------------

static void reportBuildTimeCapabilities()
{
  Serial.println("[1] Capacidade declarada pelo SDK (macros de compilacao)");
  Serial.println();
  Serial.println("  -- identificacao do alvo --");

#ifdef CONFIG_IDF_TARGET
  printMacroName("CONFIG_IDF_TARGET");
  Serial.print("\"");
  Serial.print(CONFIG_IDF_TARGET);
  Serial.println("\"");
#else
  reportMacroAbsent("CONFIG_IDF_TARGET", false, NULL);
#endif

#ifdef CONFIG_IDF_TARGET_ESP32
  reportMacroValue("CONFIG_IDF_TARGET_ESP32", (long)(CONFIG_IDF_TARGET_ESP32),
                   "ESP32 classico (LX6, sem DMA no AES, sem GCM no acelerador)");
#endif
#ifdef CONFIG_IDF_TARGET_ESP32S2
  reportMacroValue("CONFIG_IDF_TARGET_ESP32S2", (long)(CONFIG_IDF_TARGET_ESP32S2),
                   "unico alvo com SOC_AES_SUPPORT_GCM");
#endif
#ifdef CONFIG_IDF_TARGET_ESP32S3
  reportMacroValue("CONFIG_IDF_TARGET_ESP32S3", (long)(CONFIG_IDF_TARGET_ESP32S3),
                   "ESP32-S3 (LX7, AES com GDMA, SEM GCM no acelerador)");
#endif

#ifdef IDF_VERSION_HEADER_REACHED
  printMacroName("ESP-IDF (versao)");
  Serial.print(ESP_IDF_VERSION_MAJOR);
  Serial.print(".");
  Serial.print(ESP_IDF_VERSION_MINOR);
  Serial.print(".");
  Serial.print(ESP_IDF_VERSION_PATCH);
  Serial.println("   <- a dependencia de MBEDTLS_HARDWARE_GCM mudou entre 4.4 e 5.x");
#else
  Serial.println("  ESP-IDF (versao)              : esp_idf_version.h nao alcancado");
#endif

  Serial.println();
  Serial.println("  -- capacidades do silicio (soc_caps.h) --");

  if (!socCapsReached) {
    Serial.println("  ATENCAO: soc/soc_caps.h NAO foi alcancado.");
    Serial.println("  Toda ausencia de macro SOC_* abaixo e INCONCLUSIVA.");
  }

#ifdef SOC_AES_SUPPORT_GCM
  reportMacroValue("SOC_AES_SUPPORT_GCM", (long)(SOC_AES_SUPPORT_GCM),
                   "acelerador AES COM assistencia a GCM");
#else
  reportMacroAbsent("SOC_AES_SUPPORT_GCM", socCapsReached,
                    "acelerador AES SEM assistencia a GCM");
#endif

#ifdef SOC_AES_SUPPORT_DMA
  reportMacroValue("SOC_AES_SUPPORT_DMA", (long)(SOC_AES_SUPPORT_DMA),
                   "AES por DMA disponivel");
#else
  reportMacroAbsent("SOC_AES_SUPPORT_DMA", socCapsReached,
                    "sem DMA: a CPU alimenta o AES bloco a bloco");
#endif

#ifdef SOC_AES_GDMA
  reportMacroValue("SOC_AES_GDMA", (long)(SOC_AES_GDMA), NULL);
#else
  reportMacroAbsent("SOC_AES_GDMA", socCapsReached, NULL);
#endif

  Serial.println();
  Serial.println("  -- configuracao do mbedTLS neste build --");

  if (!mbedtlsConfigReached) {
    Serial.println("  ATENCAO: a configuracao do mbedTLS nao foi alcancada.");
    Serial.println("  Toda ausencia de macro MBEDTLS_* abaixo e INCONCLUSIVA.");
  }

#ifdef CONFIG_MBEDTLS_HARDWARE_AES
  reportMacroValue("CONFIG_MBEDTLS_HARDWARE_AES", (long)(CONFIG_MBEDTLS_HARDWARE_AES),
                   "bloco AES executado no periferico");
#else
  reportMacroAbsent("CONFIG_MBEDTLS_HARDWARE_AES", mbedtlsConfigReached,
                    "AES puramente em software");
#endif

#ifdef CONFIG_MBEDTLS_HARDWARE_GCM
  reportMacroValue("CONFIG_MBEDTLS_HARDWARE_GCM", (long)(CONFIG_MBEDTLS_HARDWARE_GCM),
                   "GCM PARCIALMENTE por hardware -- o GHASH continua em software");
#else
  reportMacroAbsent("CONFIG_MBEDTLS_HARDWARE_GCM", mbedtlsConfigReached,
                    "sem assistencia de hardware ao GCM");
#endif

#ifdef MBEDTLS_AES_ALT
  reportMacroFlag("MBEDTLS_AES_ALT",
                  "mbedtls_aes_* redirecionado para o port do ESP-IDF");
#else
  reportMacroAbsent("MBEDTLS_AES_ALT", mbedtlsConfigReached,
                    "mbedtls_aes_* e a implementacao em software do mbedTLS");
#endif

  /* CUIDADO. MBEDTLS_GCM_ALT definida significa apenas que mbedtls_gcm_* aponta
   * para esp_aes_gcm.c, o port do ESP-IDF. NAO significa que o GCM seja
   * acelerado por hardware: em esp_config.h a macro e definida sempre que
   * CONFIG_MBEDTLS_HARDWARE_AES estiver ativa, sem qualquer relacao com
   * SOC_AES_SUPPORT_GCM. Quem decide se o GHASH vai para o hardware e
   * CONFIG_MBEDTLS_HARDWARE_GCM, e ainda assim so parcialmente. */
#ifdef MBEDTLS_GCM_ALT
  reportMacroFlag("MBEDTLS_GCM_ALT",
                  "mbedtls_gcm_* usa o port do ESP-IDF -- NAO indica GCM por hardware");
#else
  reportMacroAbsent("MBEDTLS_GCM_ALT", mbedtlsConfigReached,
                    "mbedtls_gcm_* e a implementacao em software do mbedTLS");
#endif
}

/* Reconstroi, a partir das macros, o caminho de codigo efetivamente compilado.
 * E a saida mais util do item [1]: em vez de deixar o leitor interpretar macros
 * soltas, diz qual funcao chama qual. */
static void reportEffectiveCodePath()
{
  Serial.println();
  Serial.println("  -- caminho de codigo do AES-GCM efetivamente compilado --");

#if !defined(MBEDTLS_GCM_ALT)
  Serial.println("  mbedtls_gcm_crypt_and_tag");
  Serial.println("    -> implementacao em software do mbedTLS (gcm.c)");
  Serial.println("       cifra por blocos via mbedtls_aes_crypt_ecb, um bloco de 16 B por chamada");
  Serial.println("       GHASH em software");
#elif defined(CONFIG_MBEDTLS_HARDWARE_GCM)
  Serial.println("  mbedtls_gcm_crypt_and_tag");
  Serial.println("    -> esp_aes_gcm_crypt_and_tag            (port do ESP-IDF)");
  Serial.println("       -> caminho com assistencia de hardware ao GCM");
  Serial.println("          o GHASH, mesmo assim, continua em SOFTWARE");
  Serial.println("          (texto do proprio Kconfig do ESP-IDF)");
#else
  Serial.println("  mbedtls_gcm_crypt_and_tag");
  Serial.println("    -> esp_aes_gcm_crypt_and_tag            (port do ESP-IDF)");
  Serial.println("       -> esp_aes_gcm_crypt_and_tag_partial_hw");
  Serial.println("          -> esp_aes_crypt_ctr             cifra AES no periferico,");
  Serial.println("                                          16 B por operacao de bloco");
  Serial.println("          -> esp_gcm_ghash / gcm_mult      GHASH em SOFTWARE (C puro)");
#endif

#if !defined(SOC_AES_SUPPORT_DMA)
  Serial.println();
  Serial.println("  Sem SOC_AES_SUPPORT_DMA: a CPU escreve 4 palavras de 32 bits (16 B),");
  Serial.println("  dispara a operacao e le 4 palavras de volta, um bloco por vez.");
#endif
}

// ---------------------------------------------------------------------------

void setup()
{
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.println("=== Verificacao: o AES-GCM e acelerado por hardware neste chip? ===");
  Serial.print("CPU: ");
  Serial.print(getCpuFrequencyMhz());
  Serial.println(" MHz");
  Serial.println();

  reportBuildTimeCapabilities();
  reportEffectiveCodePath();

  Serial.println();
  Serial.println("[2] Evidencia empirica (custo marginal por bloco de 16 B)");
  Serial.print("  Medindo... (piso de ciclos, ");
  Serial.print(ITERATIONS);
  Serial.println(" medidas por ponto)");

  uint32_t asconFloor16 = floorAscon(16, ITERATIONS);
  uint32_t asconFloor32 = floorAscon(32, ITERATIONS);
  uint32_t asconFloor64 = floorAscon(64, ITERATIONS);

  uint32_t ecbFloor16 = floorAesEcbPerBlock(16, ITERATIONS);
  uint32_t ecbFloor32 = floorAesEcbPerBlock(32, ITERATIONS);
  uint32_t ecbFloor64 = floorAesEcbPerBlock(64, ITERATIONS);

  uint32_t ctrFloor16 = floorAesCtr(16, ITERATIONS);
  uint32_t ctrFloor32 = floorAesCtr(32, ITERATIONS);
  uint32_t ctrFloor64 = floorAesCtr(64, ITERATIONS);

  uint32_t gcmFloor16 = floorAesGcm(16, ITERATIONS);
  uint32_t gcmFloor32 = floorAesGcm(32, ITERATIONS);
  uint32_t gcmFloor64 = floorAesGcm(64, ITERATIONS);

  if (measurementFailed) {
    Serial.println();
    Serial.println("  ALGUMA MEDICAO FALHOU -- os numeros abaixo nao valem. Corrija antes de concluir.");
    return;
  }

  Serial.println();
  printPath("AES-ECB (bloco a bloco) ", ecbFloor16, ecbFloor32, ecbFloor64);
  printPath("AES-CTR (so cifra AES)  ", ctrFloor16, ctrFloor32, ctrFloor64);
  printPath("AES-GCM (cifra + GHASH) ", gcmFloor16, gcmFloor32, gcmFloor64);
  printPath("Ascon-128a (software)   ", asconFloor16, asconFloor32, asconFloor64);

  double ecbPerBlock   = marginalPerBlock(ecbFloor16, ecbFloor64);
  double ctrPerBlock   = marginalPerBlock(ctrFloor16, ctrFloor64);
  double gcmPerBlock   = marginalPerBlock(gcmFloor16, gcmFloor64);
  double asconPerBlock = marginalPerBlock(asconFloor16, asconFloor64);
  double ghashPerBlock = gcmPerBlock - ctrPerBlock;
  double portOverheadPerBlock = ecbPerBlock - ctrPerBlock;

  double worstLinearity = linearityDivergencePercent(ctrFloor16, ctrFloor32, ctrFloor64);
  double gcmLinearity   = linearityDivergencePercent(gcmFloor16, gcmFloor32, gcmFloor64);

  if (gcmLinearity > worstLinearity) {
    worstLinearity = gcmLinearity;
  }

  Serial.println();
  Serial.println("--- Derivacoes ---");

  Serial.print("  Custo do GHASH por bloco (GCM - CTR)          : ");
  Serial.print(ghashPerBlock, 1);
  Serial.print(" ciclos (~");
  Serial.print(cyclesToMicroseconds(ghashPerBlock), 2);
  Serial.println(" us)");

  Serial.print("  Sobrecarga da camada de port (ECB - CTR)      : ");
  Serial.print(portOverheadPerBlock, 1);
  Serial.println(" ciclos por bloco");

  Serial.print("  Ascon-128a completo, por bloco               : ");
  Serial.print(asconPerBlock, 1);
  Serial.println(" ciclos");

  if (ctrPerBlock > 0.0) {
    Serial.print("  Proporcao GHASH / cifra AES                   : ");
    Serial.print(ghashPerBlock / ctrPerBlock, 2);
    Serial.println("x");
  }

  Serial.print("  Regua: bloco AES documentado no TRM 14.3.5    : ate ");
  Serial.print(TRM_BLOCK_CYCLES_MAX);
  Serial.println(" ciclos");

  Serial.println();
  Serial.println("--- Conclusao ---");

  if (worstLinearity > 1.0) {
    Serial.print("  ATENCAO: o ponto de 32 B desvia ");
    Serial.print(worstLinearity, 2);
    Serial.println("% da reta 16->64 B.");
    Serial.println("  O modelo linear nao descreve bem os dados, entao a subtracao");
    Serial.println("  (GCM - CTR) NAO isola o GHASH de forma confiavel. Investigue antes de concluir.");
    return;
  }

  Serial.print("  Modelo linear valido (desvio maximo em 32 B: ");
  Serial.print(worstLinearity, 2);
  Serial.println("%), a subtracao isola o GHASH.");
  Serial.println();

  if (ghashPerBlock < 0.0) {
    Serial.println("  Valor negativo: o caminho CTR saiu mais caro que o GCM, o que e");
    Serial.println("  impossivel se o GCM contem o CTR. Ha erro de medicao; nao conclua nada.");
  }
  else if (ghashPerBlock <= 10.0 * TRM_BLOCK_CYCLES_MAX) {
    Serial.print("  O GHASH custa ");
    Serial.print(ghashPerBlock, 0);
    Serial.print(" ciclos por bloco, da mesma ordem do proprio bloco AES (");
    Serial.print(TRM_BLOCK_CYCLES_MAX);
    Serial.println(" ciclos).");
    Serial.println("  Isso e compativel com autenticacao acelerada por HARDWARE.");
    Serial.println("  => a afirmacao do texto precisaria ser revista NESTE chip.");
  }
  else {
    Serial.print("  O GHASH custa ");
    Serial.print(ghashPerBlock, 0);
    Serial.print(" ciclos por bloco, ");
    Serial.print(ghashPerBlock / (double) TRM_BLOCK_CYCLES_MAX, 0);
    Serial.println("x o custo do proprio bloco AES.");
    Serial.println("  Essa e a ordem de grandeza de uma multiplicacao em GF(2^128) por");
    Serial.println("  tabelas, executada na CPU -- ou seja, em SOFTWARE.");
    Serial.println("  => confirma: o GCM NAO e totalmente acelerado por hardware aqui.");
  }

  Serial.println();
  Serial.println("  Nota sobre a sobrecarga de port: ela aparece uma vez por CHAMADA tanto");
  Serial.println("  no CTR quanto no GCM (ambos passam por esp_aes_crypt_ctr), logo entra na");
  Serial.println("  parcela FIXA e se cancela na subtracao. O caminho ECB acima existe apenas");
  Serial.println("  para exibir quanto essa sobrecarga custaria se fosse paga por bloco.");
}

void loop()
{
  delay(1000);
}
