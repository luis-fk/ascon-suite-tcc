#include "AsconSecureInterno.h"

using namespace ascon_interno;

static AsconBytes emptyResult(AsconSecureStatus status)
{
  AsconBytes result;
  memset(result.data, 0, sizeof(result.data));
  result.length = 0;
  result.status = status;
  return result;
}

AsconPacket asconSecurePack(const void *payload, size_t payloadLength)
{
  AsconBytes result;
  memset(result.data, 0, sizeof(result.data));

  result.status = asconSecureWrap((const uint8_t *) payload, payloadLength,
                                  NULL, 0,
                                  result.data, sizeof(result.data),
                                  &result.length);

  if (result.status != ASCON_SECURE_OK) {
    logStatus("pacote nao gerado", -1, result.status);
    return emptyResult(result.status);
  }

  return result;
}

AsconPacket asconSecurePack(const char *text)
{
  if (text == NULL) {
    logStatus("pacote nao gerado", -1, ASCON_SECURE_ERR_BUFFER);
    return emptyResult(ASCON_SECURE_ERR_BUFFER);
  }

  return asconSecurePack((const void *) text, strlen(text));
}

AsconMessage asconSecureOpen(uint8_t peerId, const void *packet, size_t packetLength)
{
  // Zero bytes e "nada chegou", entao da para chamar Open em toda volta do
  // loop sem encher a serial de erro.
  if (packetLength == 0) {
    return emptyResult(ASCON_SECURE_EMPTY);
  }

  AsconBytes result;
  memset(result.data, 0, sizeof(result.data));

  // Capacidade MAX_PAYLOAD e nao sizeof(data): sobra sempre um byte zerado
  // depois da mensagem, que assim sai terminada em NUL.
  result.status = asconSecureUnwrap(peerId,
                                    (const uint8_t *) packet, packetLength,
                                    NULL, 0,
                                    result.data, ASCON_SECURE_MAX_PAYLOAD,
                                    &result.length);

  if (result.status != ASCON_SECURE_OK) {
    logStatus("mensagem descartada do no", peerId, result.status);
    return emptyResult(result.status);
  }

  return result;
}
