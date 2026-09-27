#include "bench_inputs.h"

#include <string.h>

uint8_t key[ASCON128_KEY_SIZE];
uint8_t nonce[ASCON128_NONCE_SIZE];
uint8_t gcmIv[12];
uint8_t plaintext[MAX_PLAINTEXT];
uint8_t ciphertext[MAX_PLAINTEXT + TAG_BYTES];
uint8_t recovered[MAX_PLAINTEXT];
uint8_t aesCiphertext[MAX_PLAINTEXT];
uint8_t aesTag[TAG_BYTES];

// Muda a cada iteracao (desloca o buffer inteiro) e a cada posicao (rampa).
// Os coeficientes so precisam ser diferentes de zero e distintos por buffer.
static void fillRamp(uint8_t *buffer, size_t length, int iteration,
                     uint8_t stepPerIteration, uint8_t stepPerByte, uint8_t offset)
{
  for (size_t index = 0; index < length; index++) {
    buffer[index] = (uint8_t)(iteration * stepPerIteration + index * stepPerByte + offset);
  }
}

static void fillConstant(uint8_t value)
{
  memset(key,       value, sizeof(key));
  memset(nonce,     value, sizeof(nonce));
  memset(gcmIv,     value, sizeof(gcmIv));
  memset(plaintext, value, sizeof(plaintext));
}

// Bytes com aparencia aleatoria, mas reproduziveis: hash do numero da iteracao.
static void fillFromHash(uint8_t *buffer, size_t length, int iteration, uint8_t domain)
{
  uint8_t seed[8] = {
    (uint8_t) iteration, (uint8_t)(iteration >> 8), (uint8_t)(iteration >> 16), (uint8_t)(iteration >> 24),
    domain, 0, 0, 0
  };
  uint8_t digest[ASCON_HASH_SIZE];
  size_t  produced = 0;

  while (produced < length) {
    seed[5] = (uint8_t)(produced / ASCON_HASH_SIZE);
    ascon_hash(digest, seed, sizeof(seed));

    size_t chunk = length - produced;
    if (chunk > ASCON_HASH_SIZE) { chunk = ASCON_HASH_SIZE; }

    memcpy(buffer + produced, digest, chunk);
    produced += chunk;
  }
}

void inputsPrepareRampKeepKey(int iteration, size_t length)
{
  fillRamp(nonce,     sizeof(nonce), iteration, 17, 3, 0);
  fillRamp(gcmIv,     sizeof(gcmIv), iteration, 19, 5, 0);
  fillRamp(plaintext, length,        iteration, 13, 5, 0);
}

void inputsPrepareRamp(int iteration, size_t length)
{
  fillRamp(key, sizeof(key), iteration, 31, 7, 1);
  inputsPrepareRampKeepKey(iteration, length);
}

void inputsPrepareClass(InputClass inputClass, int iteration, size_t length)
{
  switch (inputClass) {
    case CLASS_ZEROS:
      fillConstant(0x00);
      break;

    case CLASS_ONES:
      fillConstant(0xFF);
      break;

    case CLASS_ALTERNATING:
      memset(key,   0x55, sizeof(key));
      memset(nonce, 0xAA, sizeof(nonce));
      memset(gcmIv, 0x55, sizeof(gcmIv));
      for (size_t index = 0; index < length; index++) {
        plaintext[index] = (index % 2 == 0) ? 0x55 : 0xAA;
      }
      break;

    case CLASS_HASH:
      fillFromHash(key,       sizeof(key),   iteration, 1);
      fillFromHash(nonce,     sizeof(nonce), iteration, 2);
      fillFromHash(gcmIv,     sizeof(gcmIv), iteration, 3);
      fillFromHash(plaintext, length,        iteration, 4);
      break;

    case CLASS_RAMP:
    default:
      inputsPrepareRamp(iteration, length);
      break;
  }
}

const char *inputsClassName(InputClass inputClass)
{
  switch (inputClass) {
    case CLASS_RAMP:        return "rampa     ";
    case CLASS_ZEROS:       return "zeros     ";
    case CLASS_ONES:        return "uns (0xFF)";
    case CLASS_ALTERNATING: return "alternado ";
    case CLASS_HASH:        return "hash      ";
    default:                return "?         ";
  }
}
