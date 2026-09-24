#include "AsconSecureInterno.h"

namespace ascon_interno {

// senderCounter e senderReserved sao lidos, comparados e incrementados em
// passos separados. Sem esta trava, duas tarefas cifrando ao mesmo tempo
// poderiam pegar o mesmo contador -- e nonce repetido quebra o Ascon.
portMUX_TYPE counterLock = portMUX_INITIALIZER_UNLOCKED;

bool     senderReady    = false;
uint8_t  senderKey[ASCON_SECURE_KEY_BYTES];
uint8_t  senderPrefix[ASCON_SECURE_PREFIX_BYTES];
uint32_t senderCounter  = 0;   // proximo valor a usar
uint32_t senderReserved = 0;   // ja gravado na NVS; sempre maior que qualquer valor usado

AsconSecureStatus loadSenderState()
{
  // Vale o resultado desta chamada: se falhar, nao cifra, mesmo que uma
  // chamada anterior tenha dado certo.
  senderReady = false;

  Preferences nvs;

  if (!nvs.begin(NVS_SENDER, false)) {
    return ASCON_SECURE_ERR_NVS;
  }

  if (!nvs.isKey(NVS_KEY)) {
    nvs.end();
    return ASCON_SECURE_ERR_NOT_PROVISIONED;
  }

  if (nvs.getBytes(NVS_KEY, senderKey, ASCON_SECURE_KEY_BYTES) != ASCON_SECURE_KEY_BYTES ||
      nvs.getBytes(NVS_PREFIX, senderPrefix, ASCON_SECURE_PREFIX_BYTES) != ASCON_SECURE_PREFIX_BYTES) {
    nvs.end();
    return ASCON_SECURE_ERR_NVS;
  }

  uint32_t reserved = nvs.getUInt(NVS_RESERVED, 0);
  nvs.end();

  // Toda reserva gravada vale pelo menos COUNTER_WINDOW. Um valor menor quer
  // dizer contador perdido, de tipo trocado ou ilegivel, e recomecar do zero
  // com a mesma chave repetiria nonces que ja foram ao ar. Melhor nao cifrar.
  if (reserved < COUNTER_WINDOW) {
    secureZero(senderKey, sizeof(senderKey));
    secureZero(senderPrefix, sizeof(senderPrefix));
    return ASCON_SECURE_ERR_NVS;
  }

  // Recomeca da reserva, nao do ultimo valor usado: tudo abaixo dela pode ter
  // ido ao ar antes de uma queda de energia.
  senderCounter  = reserved;
  senderReserved = reserved;
  senderReady    = true;

  return ASCON_SECURE_OK;
}

}  // namespace ascon_interno

using namespace ascon_interno;

// Grava na NVS um valor 32 a frente do contador ANTES de usa-lo. Como o valor
// gravado e sempre maior que qualquer contador ja usado, uma queda de energia
// joga fora ate 32 valores, mas nunca repete um. Gravar a cada mensagem daria
// a mesma garantia com 32 vezes mais desgaste da flash.
static AsconSecureStatus reserveCounters()
{
  Preferences nvs;

  if (!nvs.begin(NVS_SENDER, false)) {
    return ASCON_SECURE_ERR_NVS;
  }

  portENTER_CRITICAL(&counterLock);
  uint32_t reservation = senderCounter + COUNTER_WINDOW;
  portEXIT_CRITICAL(&counterLock);

  // A gravacao pode bloquear, entao fica fora da secao critica.
  if (nvs.putUInt(NVS_RESERVED, reservation) == 0) {
    nvs.end();
    return ASCON_SECURE_ERR_NVS;
  }

  nvs.end();

  portENTER_CRITICAL(&counterLock);
  if (reservation > senderReserved) { senderReserved = reservation; }
  portEXIT_CRITICAL(&counterLock);

  return ASCON_SECURE_OK;
}

AsconSecureStatus asconSecureBegin()
{
  AsconSecureStatus status = loadSenderState();
  logStatus("Begin falhou, nada sera cifrado", -1, status);
  return status;
}

AsconSecureStatus asconSecureWrap(const uint8_t *payload, size_t payloadLength,
                                  const uint8_t *header,  size_t headerLength,
                                  uint8_t *packet, size_t packetCapacity,
                                  size_t *packetLength)
{
  // Antes de qualquer recusa: quem ignorar o retorno encontra 0 bytes para
  // transmitir, e nao o que havia na variavel.
  if (packetLength != NULL) {
    *packetLength = 0;
  }

  if (!senderReady) {
    return ASCON_SECURE_ERR_NOT_READY;
  }

  if (payload == NULL || packet == NULL || packetLength == NULL) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  if (header == NULL && headerLength > 0) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  if (payloadLength > ASCON_SECURE_MAX_PAYLOAD ||
      packetCapacity < payloadLength + ASCON_SECURE_OVERHEAD) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  // O texto claro vai ser copiado para dentro de packet antes da cifragem; um
  // header ali dentro seria sobrescrito antes de ser autenticado.
  if (rangesOverlap(header, headerLength, packet, packetCapacity)) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  portENTER_CRITICAL(&counterLock);
  bool exhausted        = senderCounter >= COUNTER_LIMIT;
  bool needsReservation = senderCounter >= senderReserved;
  portEXIT_CRITICAL(&counterLock);

  if (exhausted) {
    return ASCON_SECURE_ERR_EXHAUSTED;
  }

  if (needsReservation) {
    AsconSecureStatus status = reserveCounters();

    if (status != ASCON_SECURE_OK) {
      return status;   // sem reserva gravada nao se cifra
    }
  }

  // Reconfere dentro da trava: outra tarefa pode ter consumido a reserva ou
  // chegado ao limite entre uma checagem e outra.
  portENTER_CRITICAL(&counterLock);

  if (senderCounter >= COUNTER_LIMIT) {
    portEXIT_CRITICAL(&counterLock);
    return ASCON_SECURE_ERR_EXHAUSTED;
  }

  if (senderCounter >= senderReserved) {
    portEXIT_CRITICAL(&counterLock);
    return ASCON_SECURE_ERR_NVS;
  }

  uint32_t counter = senderCounter++;

  portEXIT_CRITICAL(&counterLock);

  uint8_t nonce[ASCON128_NONCE_SIZE];
  buildNonce(nonce, senderPrefix, counter);

  // payload e packet podem se sobrepor -- por exemplo, se alguem passar o
  // pacote anterior de volta ao Pack. Ler de um lugar e escrever em outro
  // sobreposto estragaria a entrada antes de ela ser lida, e a tag
  // autenticaria o texto estragado. Por isso o texto claro e movido primeiro
  // para a posicao final e cifrado no lugar, o que o Ascon permite; o contador
  // so e escrito no fim.
  uint8_t *cipherStart = packet + ASCON_SECURE_COUNTER_BYTES;
  memmove(cipherStart, payload, payloadLength);

  size_t cipherLength = 0;
  ascon128a_aead_encrypt(cipherStart, &cipherLength,
                         cipherStart, payloadLength,
                         header, headerLength,
                         nonce, senderKey);

  secureZero(nonce, sizeof(nonce));

  writeCounterBE(packet, counter);
  *packetLength = ASCON_SECURE_COUNTER_BYTES + cipherLength;

  return ASCON_SECURE_OK;
}
