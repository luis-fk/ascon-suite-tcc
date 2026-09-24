// AsconSecure -- camada de seguranca Ascon-128a para enlace LoRa no ESP32.
//
//   Provisionamento (uma vez por no, na bancada):  asconSecureProvision()
//   Emissor:   asconSecureBegin()         -> asconSecurePack()
//   Receptor:  asconSecureReceiverBegin() -> asconSecureAddPeer() -> asconSecureOpen()
//
// Pacote no ar: [ contador 4 B ][ texto cifrado ][ tag 16 B ]
//
// O nonce tem 16 bytes, mas so o contador viaja. O receptor monta o resto com o
// prefixo de 12 bytes que recebeu no provisionamento, e isso poupa 12 bytes por
// mensagem. O contador nao precisa de protecao a parte: ele e o nonce, e mudar
// um bit dele faz a tag falhar.

#ifndef ASCON_SECURE_H
#define ASCON_SECURE_H

#include <Arduino.h>

#define ASCON_SECURE_KEY_BYTES      16
#define ASCON_SECURE_PREFIX_BYTES   12
#define ASCON_SECURE_COUNTER_BYTES   4
#define ASCON_SECURE_TAG_BYTES      16

// Custo fixo por mensagem, somado ao payload.
#define ASCON_SECURE_OVERHEAD (ASCON_SECURE_COUNTER_BYTES + ASCON_SECURE_TAG_BYTES)

// Para mudar, edite aqui e nao no sketch. A biblioteca e compilada a parte, e
// um valor diferente de cada lado mudaria o tamanho de AsconBytes so de um
// lado -- o que corrompe a memoria sem dar erro nenhum.
#ifdef ASCON_SECURE_MAX_PAYLOAD
#error "Nao defina ASCON_SECURE_MAX_PAYLOAD no sketch: edite o valor em AsconSecure.h."
#endif
#define ASCON_SECURE_MAX_PAYLOAD 200

// Tamanho para o buffer de recepcao do radio.
#define ASCON_SECURE_MAX_PACKET (ASCON_SECURE_MAX_PAYLOAD + ASCON_SECURE_OVERHEAD)

typedef enum {
  ASCON_SECURE_OK                  =   0,
  ASCON_SECURE_ERR_NOT_READY       =  -1,
  ASCON_SECURE_ERR_BUFFER          =  -2,
  ASCON_SECURE_ERR_AUTH            =  -3,
  ASCON_SECURE_ERR_REPLAY          =  -4,
  ASCON_SECURE_ERR_NVS             =  -5,
  ASCON_SECURE_ERR_RNG             =  -6,
  ASCON_SECURE_ERR_EXHAUSTED       =  -7,
  ASCON_SECURE_ERR_PEER            =  -8,
  ASCON_SECURE_ERR_FULL            =  -9,
  ASCON_SECURE_ERR_NOT_PROVISIONED = -10,
  ASCON_SECURE_EMPTY               =   1,   // pacote de 0 bytes: nada chegou, nao e erro
} AsconSecureStatus;

// Os bytes ficam dentro do resultado, entao ele pode ser guardado e usado
// depois sem mudar numa chamada seguinte. `if (resultado)` so e verdadeiro
// quando deu certo; em qualquer falha, length e 0 e data vem zerado.
struct AsconBytes {
  uint8_t           data[ASCON_SECURE_MAX_PACKET];
  size_t            length;
  AsconSecureStatus status;

  explicit operator bool() const { return status == ASCON_SECURE_OK; }
};

typedef AsconBytes AsconPacket;    // o que o emissor entrega ao radio
typedef AsconBytes AsconMessage;   // o que o receptor entrega a aplicacao

// Com isto ligado a biblioteca explica sozinha, na serial, por que algo falhou
// ou por que uma mensagem foi descartada. Wrap e Unwrap, a camada crua, nao
// registram nada: quem usa essas duas trata o codigo de retorno.
void asconSecureLogTo(Print &out);

// ---------------------------------------------------------------------------
// Provisionamento -- so no sketch Provisionamento, na bancada
// ---------------------------------------------------------------------------

// Na primeira vez gera chave e prefixo NESTA placa e guarda na NVS; nas outras
// so carrega o que ja existe.
//
// Chame antes de iniciar ADC, Wi-Fi ou Bluetooth. A geracao usa o SAR ADC como
// fonte de entropia, e o ESP-IDF nao permite usa-lo ao mesmo tempo que esses
// perifericos. E por isso que so esta funcao gera chave, e nao o Begin.
AsconSecureStatus asconSecureProvision();

// Imprime o bloco que vai no Receptor. Mostra a chave: so em bancada.
void asconSecurePrintProvisioning();

// Apaga chave, prefixo e contador desta placa. Depois ela precisa ser
// provisionada de novo, e o Receptor precisa do bloco novo.
AsconSecureStatus asconSecureFactoryReset();

// ---------------------------------------------------------------------------
// Emissor
// ---------------------------------------------------------------------------

// Carrega a chave gravada no provisionamento. Nunca gera uma: numa placa sem
// provisionamento devolve ASCON_SECURE_ERR_NOT_PROVISIONED, em vez de criar em
// silencio uma chave que o receptor nao conhece.
AsconSecureStatus asconSecureBegin();

// ---------------------------------------------------------------------------
// Receptor
// ---------------------------------------------------------------------------

AsconSecureStatus asconSecureReceiverBegin();

// Registra um no com o bloco que o provisionamento dele imprimiu.
AsconSecureStatus asconSecureAddPeer(uint8_t peerId,
                                     const uint8_t key[ASCON_SECURE_KEY_BYTES],
                                     const uint8_t prefix[ASCON_SECURE_PREFIX_BYTES]);

// ---------------------------------------------------------------------------
// Atalhos -- o jeito recomendado de usar
//
// Para ficar seguro nao e preciso checar codigo de retorno: se falhou, o
// resultado e falso e nao ha bytes para usar. Checar so serve para saber o
// motivo, e asconSecureLogTo() ja mostra.
//
// Para retransmitir um pacote, mande pacote.data de novo; nao o passe ao Pack,
// que o cifraria como uma leitura nova. Se as duas copias chegarem, a segunda
// e descartada como replay, e isso esta certo.
// ---------------------------------------------------------------------------

//   AsconPacket pacote = asconSecurePack("temp=23.5C");
//   if (pacote) { radio.transmit(pacote.data, pacote.length); }
//
// So texto terminado em NUL. Dado binario pode ter um byte 0 no meio, que
// cortaria o resto em silencio: para ele use a forma com tamanho.
AsconPacket asconSecurePack(const char *text);

//   struct __attribute__((packed)) Leitura { int16_t temp; uint16_t lux; uint8_t bat; };
//   AsconPacket pacote = asconSecurePack(&leitura, sizeof(leitura));
//
// Sem o packed o compilador poe um byte de enchimento e a struct fica com 6.
AsconPacket asconSecurePack(const void *payload, size_t payloadLength);

//   AsconMessage leitura = asconSecureOpen(NO_SENSOR, pacote, tamanho);
//   if (leitura) { Serial.write(leitura.data, leitura.length); }
//
// pacote e tamanho vem do radio. O tamanho e obrigatorio porque o pacote
// cifrado e binario -- ja comeca com 00 00 00, do contador. A mensagem
// devolvida vem terminada em NUL e pode ser lida como texto.
AsconMessage asconSecureOpen(uint8_t peerId, const void *packet, size_t packetLength);

// ---------------------------------------------------------------------------
// Camada crua
// ---------------------------------------------------------------------------

// payload e packet podem ser o mesmo buffer; header nao pode apontar para
// dentro de packet. Em qualquer erro, *packetLength vale 0.
AsconSecureStatus asconSecureWrap(const uint8_t *payload, size_t payloadLength,
                                  const uint8_t *header,  size_t headerLength,
                                  uint8_t *packet, size_t packetCapacity,
                                  size_t *packetLength);

// Em qualquer erro, nada e escrito em payload e *payloadLength vale 0.
AsconSecureStatus asconSecureUnwrap(uint8_t peerId,
                                    const uint8_t *packet, size_t packetLength,
                                    const uint8_t *header, size_t headerLength,
                                    uint8_t *payload, size_t payloadCapacity,
                                    size_t *payloadLength);

const char *asconSecureStatusText(AsconSecureStatus status);

#endif
