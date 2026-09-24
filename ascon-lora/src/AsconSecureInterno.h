// Uso interno da biblioteca: nao inclua no sketch.

#ifndef ASCON_SECURE_INTERNO_H
#define ASCON_SECURE_INTERNO_H

#include "AsconSecure.h"

#include <ASCON.h>
#include <Preferences.h>
#include <string.h>

// Emissor e receptor em namespaces separados da NVS, para que uma mesma placa
// possa ter os dois papeis sem um apagar o estado do outro.
#define NVS_SENDER   "ascon-sec"
#define NVS_RECEIVER "ascon-rx"

#define NVS_KEY      "k"
#define NVS_PREFIX   "p"
#define NVS_RESERVED "ctr"

#define COUNTER_WINDOW 32

// Para antes de o contador de 32 bits dar a volta, que repetiria nonce.
#define COUNTER_LIMIT  0xFFFFF000u

#define MAX_PEERS 8

namespace ascon_interno {

// Estado do emissor. Definido em AsconSecureEmissor.cpp e usado tambem pelo
// provisionamento, que imprime e apaga a chave.
extern portMUX_TYPE counterLock;
extern bool         senderReady;
extern uint8_t      senderKey[ASCON_SECURE_KEY_BYTES];
extern uint8_t      senderPrefix[ASCON_SECURE_PREFIX_BYTES];
extern uint32_t     senderCounter;
extern uint32_t     senderReserved;

AsconSecureStatus loadSenderState();

extern Print *logSink;
void logStatus(const char *context, int peerId, AsconSecureStatus status);

void     writeCounterBE(uint8_t *out, uint32_t value);
uint32_t readCounterBE(const uint8_t *in);
void     secureZero(void *memory, size_t length);
bool     rangesOverlap(const void *a, size_t aLength, const void *b, size_t bLength);

void buildNonce(uint8_t nonce[ASCON128_NONCE_SIZE],
                const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES],
                uint32_t counter);

void keyFingerprint(uint8_t out[8],
                    const uint8_t key[ASCON_SECURE_KEY_BYTES],
                    const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES]);

}  // namespace ascon_interno

#endif
