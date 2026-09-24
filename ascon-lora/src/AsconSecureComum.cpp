#include "AsconSecureInterno.h"

namespace ascon_interno {

Print *logSink = NULL;

// Sai como "asconSecure: <contexto>[ <no>]: <motivo>". peerId < 0 omite o no.
void logStatus(const char *context, int peerId, AsconSecureStatus status)
{
  if (logSink == NULL || status == ASCON_SECURE_OK || status == ASCON_SECURE_EMPTY) {
    return;
  }

  logSink->print("asconSecure: ");
  logSink->print(context);

  if (peerId >= 0) {
    logSink->print(" ");
    logSink->print(peerId);
  }

  logSink->print(": ");
  logSink->println(asconSecureStatusText(status));
}

// Escrito byte a byte, e nao com memcpy do uint32_t, para que o formato no ar
// nao dependa da arquitetura de quem manda nem de quem recebe.
void writeCounterBE(uint8_t *out, uint32_t value)
{
  out[0] = (uint8_t)(value >> 24);
  out[1] = (uint8_t)(value >> 16);
  out[2] = (uint8_t)(value >> 8);
  out[3] = (uint8_t)(value);
}

uint32_t readCounterBE(const uint8_t *in)
{
  return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
         ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
}

// Um memset num buffer que deixa de ser usado logo depois e removido pelo
// otimizador, e o Arduino compila com otimizacao: chave e nonce ficariam na
// pilha. Escrevendo por um ponteiro volatile, o compilador e obrigado a manter
// cada escrita.
void secureZero(void *memory, size_t length)
{
  volatile uint8_t *cursor = (volatile uint8_t *) memory;
  while (length--) {
    *cursor++ = 0;
  }
}

bool rangesOverlap(const void *a, size_t aLength, const void *b, size_t bLength)
{
  if (aLength == 0 || bLength == 0) {
    return false;
  }

  uintptr_t aStart = (uintptr_t) a, bStart = (uintptr_t) b;
  return aStart < bStart + bLength && bStart < aStart + aLength;
}

// nonce = prefixo(12) || contador(4)
void buildNonce(uint8_t nonce[ASCON128_NONCE_SIZE],
                const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES],
                uint32_t counter)
{
  memcpy(nonce, prefix, ASCON_SECURE_PREFIX_BYTES);
  writeCounterBE(nonce + ASCON_SECURE_PREFIX_BYTES, counter);
}

// Identidade de 8 bytes da chave. Nao e segredo: o receptor usa para guardar
// o contador de cada chave e para notar configuracoes trocadas.
void keyFingerprint(uint8_t out[8],
                    const uint8_t key[ASCON_SECURE_KEY_BYTES],
                    const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES])
{
  uint8_t material[ASCON_SECURE_KEY_BYTES + ASCON_SECURE_PREFIX_BYTES];
  uint8_t digest[ASCON_HASH_SIZE];

  memcpy(material, key, ASCON_SECURE_KEY_BYTES);
  memcpy(material + ASCON_SECURE_KEY_BYTES, prefix, ASCON_SECURE_PREFIX_BYTES);

  ascon_hash(digest, material, sizeof(material));
  memcpy(out, digest, 8);

  secureZero(material, sizeof(material));
  secureZero(digest, sizeof(digest));
}

}  // namespace ascon_interno

using namespace ascon_interno;

void asconSecureLogTo(Print &out)
{
  logSink = &out;
}

const char *asconSecureStatusText(AsconSecureStatus status)
{
  switch (status) {
    case ASCON_SECURE_OK:                  return "ok";
    case ASCON_SECURE_ERR_NOT_READY:       return "nao inicializado";
    case ASCON_SECURE_ERR_BUFFER:          return "buffer invalido";
    case ASCON_SECURE_ERR_AUTH:            return "tag invalida: adulterada, ou chave ou tamanho diferentes dos do emissor";
    case ASCON_SECURE_ERR_REPLAY:          return "contador repetido (replay)";
    case ASCON_SECURE_ERR_NVS:             return "falha na memoria nao volatil";
    case ASCON_SECURE_ERR_RNG:             return "falha do gerador aleatorio";
    case ASCON_SECURE_ERR_EXHAUSTED:       return "contador esgotado: trocar a chave";
    case ASCON_SECURE_ERR_PEER:            return "no nao registrado (id errado, ou faltou asconSecureAddPeer)";
    case ASCON_SECURE_ERR_FULL:            return "tabela de nos cheia (maximo 8)";
    case ASCON_SECURE_ERR_NOT_PROVISIONED: return "placa nao provisionada: grave o sketch Provisionamento antes";
    case ASCON_SECURE_EMPTY:               return "pacote vazio";
  }
  return "desconhecido";
}
