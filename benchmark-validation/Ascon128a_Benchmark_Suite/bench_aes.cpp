#include "bench_aes.h"
#include "bench_inputs.h"

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include <string.h>

// soc_caps.h define as capacidades do silicio (SOC_AES_SUPPORT_GCM etc.).
#if defined(__has_include)
#  if __has_include("soc/soc_caps.h")
#    include "soc/soc_caps.h"
#  endif
#endif

uint32_t aesDecryptFailures = 0;
bool     aesApiError        = false;

static mbedtls_gcm_context gcmContext;
static mbedtls_aes_context aesContext;

// Estado do modo CTR, zerado a cada preparo.
static uint8_t ctrNonceCounter[16];
static uint8_t ctrStreamBlock[16];
static size_t  ctrOffset = 0;

// ---------------------------------------------------------------------------
// GCM
// ---------------------------------------------------------------------------

// A chave e fixada uma vez por execucao, que e o caso real: um no tem uma
// chave. O custo do setkey fica fora da medicao dos dois lados.
static void gcmBeginRun(size_t length)
{
  inputsPrepareRamp(0, length);
  mbedtls_gcm_init(&gcmContext);
  if (mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) { aesApiError = true; }
}

static void gcmEndRun(size_t)
{
  mbedtls_gcm_free(&gcmContext);
}

static void gcmEncryptOperation(size_t length)
{
  int status = mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, length,
                                         gcmIv, sizeof(gcmIv), NULL, 0,
                                         plaintext, aesCiphertext, TAG_BYTES, aesTag);
  if (status != 0) { aesApiError = true; }
}

static void gcmDecryptPrepare(int iteration, size_t length)
{
  inputsPrepareRampKeepKey(iteration, length);
  gcmEncryptOperation(length);
}

static void gcmDecryptOperation(size_t length)
{
  int status = mbedtls_gcm_auth_decrypt(&gcmContext, length, gcmIv, sizeof(gcmIv), NULL, 0,
                                        aesTag, TAG_BYTES, aesCiphertext, recovered);
  if (status != 0) { aesDecryptFailures++; }
}

// ---------------------------------------------------------------------------
// CTR
// ---------------------------------------------------------------------------

static void aesBeginRun(size_t length)
{
  inputsPrepareRamp(0, length);
  mbedtls_aes_init(&aesContext);
  if (mbedtls_aes_setkey_enc(&aesContext, key, 128) != 0) { aesApiError = true; }
}

static void aesEndRun(size_t)
{
  mbedtls_aes_free(&aesContext);
}

static void ctrPrepare(int iteration, size_t length)
{
  inputsPrepareRampKeepKey(iteration, length);
  memcpy(ctrNonceCounter, gcmIv, 12);
  memset(ctrNonceCounter + 12, 0, 4);
  memset(ctrStreamBlock, 0, sizeof(ctrStreamBlock));
  ctrOffset = 0;
}

static void ctrOperation(size_t length)
{
  int status = mbedtls_aes_crypt_ctr(&aesContext, length, &ctrOffset,
                                     ctrNonceCounter, ctrStreamBlock, plaintext, aesCiphertext);
  if (status != 0) { aesApiError = true; }
}

const BenchSpec aesGcmEncryptSpec = { "AES-128-GCM cifra  ", gcmBeginRun, inputsPrepareRampKeepKey, gcmEncryptOperation,  gcmEndRun };
const BenchSpec aesGcmDecryptSpec = { "AES-128-GCM decifra", gcmBeginRun, gcmDecryptPrepare,        gcmDecryptOperation,  gcmEndRun };
const BenchSpec aesCtrSpec        = { "AES-128-CTR        ", aesBeginRun, ctrPrepare,               ctrOperation,         aesEndRun };

// ---------------------------------------------------------------------------
// Autoteste
// ---------------------------------------------------------------------------

// GCM Test Case 2: K = 0^128, IV = 0^96, P = 0^128.
static const uint8_t gcmExpectedCiphertext[16] = {
  0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78
};
static const uint8_t gcmExpectedTag[16] = {
  0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
};

bool aesSelfCheck(uint32_t *firstEncryptCycles, uint32_t *firstDecryptCycles)
{
  memset(key,       0, sizeof(key));
  memset(gcmIv,     0, sizeof(gcmIv));
  memset(plaintext, 0, 16);

  mbedtls_gcm_init(&gcmContext);
  int setkeyStatus = mbedtls_gcm_setkey(&gcmContext, MBEDTLS_CIPHER_ID_AES, key, 128);

  uint32_t startCycles = ESP.getCycleCount();
  int encryptStatus = mbedtls_gcm_crypt_and_tag(&gcmContext, MBEDTLS_GCM_ENCRYPT, 16,
                                                gcmIv, sizeof(gcmIv), NULL, 0,
                                                plaintext, aesCiphertext, TAG_BYTES, aesTag);
  *firstEncryptCycles = ESP.getCycleCount() - startCycles;

  bool encryptOk = (setkeyStatus == 0) && (encryptStatus == 0) &&
                   memcmp(aesCiphertext, gcmExpectedCiphertext, 16) == 0 &&
                   memcmp(aesTag, gcmExpectedTag, 16) == 0;

  memset(recovered, 0xA5, sizeof(recovered));
  startCycles = ESP.getCycleCount();
  int decryptStatus = mbedtls_gcm_auth_decrypt(&gcmContext, 16, gcmIv, sizeof(gcmIv), NULL, 0,
                                               aesTag, TAG_BYTES, aesCiphertext, recovered);
  *firstDecryptCycles = ESP.getCycleCount() - startCycles;
  bool decryptOk = (decryptStatus == 0) && memcmp(recovered, plaintext, 16) == 0;

  aesTag[15] ^= 0x01;
  int tamperStatus = mbedtls_gcm_auth_decrypt(&gcmContext, 16, gcmIv, sizeof(gcmIv), NULL, 0,
                                              aesTag, TAG_BYTES, aesCiphertext, recovered);
  aesTag[15] ^= 0x01;
  bool tamperOk = (tamperStatus != 0);

  mbedtls_gcm_free(&gcmContext);

  Serial.printf("  AES-128-GCM Test Case 2 (PT=16)   : cifra %s | decifra %s | tag adulterada %s\n",
                encryptOk ? "OK" : "FALHOU",
                decryptOk ? "OK" : "FALHOU",
                tamperOk  ? "recusada" : "ACEITA (FALHOU)");

  return encryptOk && decryptOk && tamperOk;
}

// ---------------------------------------------------------------------------
// Capacidade declarada pelo SDK
// ---------------------------------------------------------------------------

// MBEDTLS_GCM_ALT fica de fora de proposito: ela so diz que o port da
// Espressif substitui o GCM do mbedTLS, e nao que ha GCM em hardware.
void aesReportBuildCapabilities()
{
#ifdef SOC_AES_SUPPORT_GCM
  Serial.println("  SOC_AES_SUPPORT_GCM         : definida   <- acelerador AES com assistencia a GCM");
#else
  Serial.println("  SOC_AES_SUPPORT_GCM         : ausente    <- acelerador AES sem assistencia a GCM");
#endif
#ifdef SOC_AES_SUPPORT_DMA
  Serial.println("  SOC_AES_SUPPORT_DMA         : definida   <- AES por DMA");
#else
  Serial.println("  SOC_AES_SUPPORT_DMA         : ausente    <- a CPU alimenta o AES bloco a bloco");
#endif
#ifdef CONFIG_MBEDTLS_HARDWARE_AES
  Serial.println("  CONFIG_MBEDTLS_HARDWARE_AES : definida   <- bloco AES no periferico");
#else
  Serial.println("  CONFIG_MBEDTLS_HARDWARE_AES : ausente    <- AES em software");
#endif
#ifdef CONFIG_MBEDTLS_HARDWARE_GCM
  Serial.println("  CONFIG_MBEDTLS_HARDWARE_GCM : definida   <- GCM parcialmente por hardware; o GHASH continua em software");
#else
  Serial.println("  CONFIG_MBEDTLS_HARDWARE_GCM : ausente    <- sem assistencia de hardware ao GCM");
#endif
}
