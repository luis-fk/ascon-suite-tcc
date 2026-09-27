#include "bench_ascon.h"
#include "bench_inputs.h"

#include <ASCON.h>
#include <string.h>

uint32_t asconDecryptFailures = 0;

static void asconEncryptOperation(size_t length)
{
  size_t ciphertextLength = 0;
  ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, length, NULL, 0, nonce, key);
}

// Um pacote valido para o tamanho e a iteracao, produzido fora da regiao medida.
static void asconDecryptPrepare(int iteration, size_t length)
{
  inputsPrepareRamp(iteration, length);
  asconEncryptOperation(length);
}

static void asconDecryptOperation(size_t length)
{
  size_t recoveredLength = 0;
  int result = ascon128a_aead_decrypt(recovered, &recoveredLength,
                                      ciphertext, length + TAG_BYTES,
                                      NULL, 0, nonce, key);
  if (result < 0) { asconDecryptFailures++; }
}

const BenchSpec asconEncryptSpec = { "Ascon-128a cifra   ", NULL, inputsPrepareRamp,   asconEncryptOperation, NULL };
const BenchSpec asconDecryptSpec = { "Ascon-128a decifra ", NULL, asconDecryptPrepare, asconDecryptOperation, NULL };

// ---------------------------------------------------------------------------
// Autoteste
// ---------------------------------------------------------------------------

// Nos dois vetores, chave, nonce, texto e AD sao a sequencia 00..0F.
static const uint8_t katSequence[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

// Count 529: PT de 16 bytes, sem AD.
static const uint8_t katExpected529[32] = {
  0x6e,0x49,0x0c,0xfe,0xd5,0xb3,0x54,0x67,0x67,0x35,0x0c,0xd8,0x3c,0x4a,0xcf,0xbd,
  0xb1,0x0f,0x61,0x1b,0x7d,0x79,0x27,0x8b,0xd8,0x06,0x7f,0xc1,0xbc,0xdf,0x39,0xbe
};

// Count 545: PT de 16 bytes, AD de 16 bytes.
static const uint8_t katExpected545[32] = {
  0x52,0x49,0x9a,0xc9,0xc8,0x43,0x23,0xa4,0xae,0x24,0xea,0xec,0xcf,0x45,0xc1,0x37,
  0x31,0x6d,0x7a,0xb1,0x77,0x24,0xba,0x67,0xa8,0x5e,0xcd,0x3c,0x04,0x57,0xc4,0x59
};

struct KatVector {
  const char    *name;
  size_t         adLength;
  const uint8_t *expected;
};

static const KatVector katVectors[] = {
  { "Count 529 (PT=16 AD=0) ",  0, katExpected529 },
  { "Count 545 (PT=16 AD=16)", 16, katExpected545 },
};

bool asconSelfCheck(uint32_t *firstEncryptCycles, uint32_t *firstDecryptCycles)
{
  bool allPassed = true;

  for (size_t index = 0; index < sizeof(katVectors) / sizeof(katVectors[0]); index++) {
    const KatVector *vector = &katVectors[index];
    const uint8_t   *ad     = vector->adLength > 0 ? katSequence : NULL;

    memcpy(key,       katSequence, sizeof(key));
    memcpy(nonce,     katSequence, sizeof(nonce));
    memcpy(plaintext, katSequence, 16);

    size_t   ciphertextLength = 0;
    uint32_t startCycles = ESP.getCycleCount();
    ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, 16,
                           ad, vector->adLength, nonce, key);
    uint32_t encryptCycles = ESP.getCycleCount() - startCycles;

    bool encryptOk = (ciphertextLength == 32) && memcmp(ciphertext, vector->expected, 32) == 0;

    memset(recovered, 0xA5, sizeof(recovered));
    size_t recoveredLength = 0;
    startCycles = ESP.getCycleCount();
    int result = ascon128a_aead_decrypt(recovered, &recoveredLength, ciphertext, 32,
                                        ad, vector->adLength, nonce, key);
    uint32_t decryptCycles = ESP.getCycleCount() - startCycles;

    bool decryptOk = (result >= 0) && (recoveredLength == 16) && memcmp(recovered, plaintext, 16) == 0;

    // Um bit da tag virado tem de ser recusado: e isso que faz o contador de
    // recusas das medicoes significar alguma coisa.
    ciphertext[31] ^= 0x01;
    result = ascon128a_aead_decrypt(recovered, &recoveredLength, ciphertext, 32,
                                    ad, vector->adLength, nonce, key);
    ciphertext[31] ^= 0x01;
    bool tamperOk = (result < 0);

    if (index == 0) {
      *firstEncryptCycles = encryptCycles;
      *firstDecryptCycles = decryptCycles;
    }

    Serial.printf("  Ascon-128a %s: cifra %s | decifra %s | tag adulterada %s\n",
                  vector->name,
                  encryptOk ? "OK" : "FALHOU",
                  decryptOk ? "OK" : "FALHOU",
                  tamperOk  ? "recusada" : "ACEITA (FALHOU)");

    allPassed = allPassed && encryptOk && decryptOk && tamperOk;
  }

  return allPassed;
}
