#include "AsconSecureInterno.h"

using namespace ascon_interno;

struct Peer {
  bool     used;
  uint8_t  id;
  uint8_t  key[ASCON_SECURE_KEY_BYTES];
  uint8_t  prefix[ASCON_SECURE_PREFIX_BYTES];
  uint8_t  fingerprint[8];
  bool     hasAccepted;    // separado de lastAccepted porque o contador 0 e valido
  uint32_t lastAccepted;
};

static bool receiverReady = false;
static Peer peers[MAX_PEERS];

static Peer *findPeer(uint8_t peerId)
{
  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i].used && peers[i].id == peerId) {
      return &peers[i];
    }
  }
  return NULL;
}

// O contador anti-replay e guardado pela CHAVE, e nao pelo numero do no. Pelo
// numero, a protecao dependia de a configuracao nunca estar errada: colar o
// mesmo bloco duas vezes, trocar os blocos de dois nos por uma ligacao ou
// renumerar um no apagava ou separava o contador, e o historico inteiro voltava
// a ser aceito. Pela chave, ela sempre encontra o mesmo contador, com qualquer
// numero, e o contador nunca e apagado.
//
// "c" + 7 bytes da impressao em hex = 15 caracteres, o maximo que a NVS aceita.
static void counterKeyFor(char out[16], const uint8_t fingerprint[8])
{
  static const char digits[] = "0123456789abcdef";

  out[0] = 'c';
  for (int i = 0; i < 7; i++) {
    out[1 + 2 * i] = digits[fingerprint[i] >> 4];
    out[2 + 2 * i] = digits[fingerprint[i] & 0x0F];
  }
  out[15] = '\0';
}

static AsconSecureStatus receiverBeginImpl()
{
  int registered = 0;
  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i].used) { registered++; }
  }

  // Acontece em rotina de reconexao, e o sintoma depois seria todo pacote
  // voltando como "no nao registrado" sem motivo aparente.
  if (registered > 0 && logSink != NULL) {
    logSink->print("asconSecure: AVISO -- ReceiverBegin chamado de novo; ");
    logSink->print(registered);
    logSink->println(" no(s) descartado(s). Chame asconSecureAddPeer de novo.");
  }

  secureZero(peers, sizeof(peers));

  // Abre em escrita so para CRIAR o namespace. Abrir somente-leitura um
  // namespace que nunca existiu falha no ESP32, e essa falha seria
  // indistinguivel de uma falha real da NVS.
  Preferences nvs;

  if (!nvs.begin(NVS_RECEIVER, false)) {
    receiverReady = false;
    return ASCON_SECURE_ERR_NVS;
  }

  nvs.end();

  receiverReady = true;
  return ASCON_SECURE_OK;
}

static AsconSecureStatus addPeerImpl(uint8_t peerId,
                                     const uint8_t key[ASCON_SECURE_KEY_BYTES],
                                     const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES])
{
  if (!receiverReady) {
    return ASCON_SECURE_ERR_NOT_READY;
  }

  if (key == NULL || prefix == NULL) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  uint8_t fingerprint[8];
  keyFingerprint(fingerprint, key, prefix);

  // Nenhum dos dois abre brecha, mas os dois sao engano de configuracao que
  // custaria tempo para achar.
  for (int i = 0; i < MAX_PEERS; i++) {
    if (!peers[i].used) { continue; }

    bool sameKey = memcmp(peers[i].fingerprint, fingerprint, sizeof(fingerprint)) == 0;

    if (sameKey && peers[i].id != peerId && logSink != NULL) {
      logSink->print("asconSecure: AVISO -- a mesma chave ja esta registrada no no ");
      logSink->print((int) peers[i].id);
      logSink->print("; o no ");
      logSink->print((int) peerId);
      logSink->println(" compartilha o mesmo contador anti-replay.");
    }

    if (!sameKey && peers[i].id == peerId && logSink != NULL) {
      logSink->print("asconSecure: AVISO -- no ");
      logSink->print((int) peerId);
      logSink->println(" registrado de novo com outra chave; a anterior foi substituida.");
      logSink->println("asconSecure: (bloco do Provisionamento colado duas vezes com o mesmo NO_SENSOR?)");
    }
  }

  Peer *peer = findPeer(peerId);

  if (peer == NULL) {
    for (int i = 0; i < MAX_PEERS; i++) {
      if (!peers[i].used) { peer = &peers[i]; break; }
    }
  }

  if (peer == NULL) {
    return ASCON_SECURE_ERR_FULL;
  }

  // O contador e lido antes de o no entrar na tabela: se a NVS falhar, ele fica
  // de fora, em vez de entrar com a protecao contra replay desligada.
  Preferences nvs;
  char counterKey[16];
  counterKeyFor(counterKey, fingerprint);

  if (!nvs.begin(NVS_RECEIVER, true)) {
    return ASCON_SECURE_ERR_NVS;
  }

  bool     hasAccepted  = nvs.isKey(counterKey);
  uint32_t lastAccepted = hasAccepted ? nvs.getUInt(counterKey, 0) : 0;
  nvs.end();

  peer->used = true;
  peer->id   = peerId;
  memcpy(peer->key,         key,         ASCON_SECURE_KEY_BYTES);
  memcpy(peer->prefix,      prefix,      ASCON_SECURE_PREFIX_BYTES);
  memcpy(peer->fingerprint, fingerprint, sizeof(fingerprint));
  peer->hasAccepted  = hasAccepted;
  peer->lastAccepted = lastAccepted;

  return ASCON_SECURE_OK;
}

AsconSecureStatus asconSecureReceiverBegin()
{
  AsconSecureStatus status = receiverBeginImpl();
  logStatus("ReceiverBegin falhou, nenhuma mensagem sera aceita", -1, status);
  return status;
}

AsconSecureStatus asconSecureAddPeer(uint8_t peerId,
                                     const uint8_t key[ASCON_SECURE_KEY_BYTES],
                                     const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES])
{
  AsconSecureStatus status = addPeerImpl(peerId, key, prefix);
  logStatus("nao foi possivel registrar o no", peerId, status);
  return status;
}

AsconSecureStatus asconSecureUnwrap(uint8_t peerId,
                                    const uint8_t *packet, size_t packetLength,
                                    const uint8_t *header, size_t headerLength,
                                    uint8_t *payload, size_t payloadCapacity,
                                    size_t *payloadLength)
{
  if (payloadLength != NULL) {
    *payloadLength = 0;
  }

  if (!receiverReady) {
    return ASCON_SECURE_ERR_NOT_READY;
  }

  if (packet == NULL || payload == NULL || payloadLength == NULL) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  if (header == NULL && headerLength > 0) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  Peer *peer = findPeer(peerId);

  if (peer == NULL) {
    return ASCON_SECURE_ERR_PEER;
  }

  // A primeira condicao protege a subtracao de baixo: packetLength e sem
  // sinal, e um pacote curto viraria um tamanho gigante.
  if (packetLength < ASCON_SECURE_OVERHEAD ||
      packetLength - ASCON_SECURE_OVERHEAD > ASCON_SECURE_MAX_PAYLOAD) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  size_t cipherLength = packetLength - ASCON_SECURE_COUNTER_BYTES;
  size_t plainLength  = packetLength - ASCON_SECURE_OVERHEAD;

  if (payloadCapacity < plainLength) {
    return ASCON_SECURE_ERR_BUFFER;
  }

  uint32_t counter = readCounterBE(packet);

  uint8_t nonce[ASCON128_NONCE_SIZE];
  buildNonce(nonce, peer->prefix, counter);

  // Decifra num buffer proprio: nada chega a quem chamou antes de a mensagem
  // passar pela tag e pelo teste de replay.
  uint8_t scratch[ASCON_SECURE_MAX_PAYLOAD];
  size_t  recovered = 0;

  int result = ascon128a_aead_decrypt(scratch, &recovered,
                                      packet + ASCON_SECURE_COUNTER_BYTES, cipherLength,
                                      header, headerLength,
                                      nonce, peer->key);

  secureZero(nonce, sizeof(nonce));

  if (result < 0) {
    secureZero(scratch, sizeof(scratch));
    return ASCON_SECURE_ERR_AUTH;
  }

  // O replay so e testado depois da tag. Na ordem inversa, um pacote forjado
  // com contador enorme, que nem passaria na tag, ja teria envenenado o estado
  // e travado o no verdadeiro.
  if (peer->hasAccepted && counter <= peer->lastAccepted) {
    secureZero(scratch, sizeof(scratch));
    return ASCON_SECURE_ERR_REPLAY;
  }

  // Grava antes de entregar. Se a mensagem saisse e a gravacao falhasse, depois
  // de um reinicio o receptor voltaria a um contador antigo e aceitaria de novo
  // tudo o que veio no meio. Perder uma mensagem e melhor que isso.
  Preferences nvs;
  char counterKey[16];
  counterKeyFor(counterKey, peer->fingerprint);

  bool persisted = false;

  if (nvs.begin(NVS_RECEIVER, false)) {
    persisted = nvs.putUInt(counterKey, counter) != 0;
    nvs.end();
  }

  if (!persisted) {
    secureZero(scratch, sizeof(scratch));
    return ASCON_SECURE_ERR_NVS;
  }

  // Todos os registros com a mesma chave andam juntos; senao, a mesma chave em
  // dois numeros aceitaria cada pacote uma vez por numero.
  for (int i = 0; i < MAX_PEERS; i++) {
    if (peers[i].used &&
        memcmp(peers[i].fingerprint, peer->fingerprint, sizeof(peer->fingerprint)) == 0) {
      peers[i].hasAccepted  = true;
      peers[i].lastAccepted = counter;
    }
  }

  memcpy(payload, scratch, recovered);
  secureZero(scratch, sizeof(scratch));

  *payloadLength = recovered;

  return ASCON_SECURE_OK;
}
