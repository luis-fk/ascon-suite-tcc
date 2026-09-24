// Gateway. NAO roda o Provisionamento: nao tem chave propria, so guarda a dos
// nos que escuta.

#include <AsconSecure.h>

// ---------------------------------------------------------------------------
// Cole aqui o bloco que o Provisionamento imprimiu, entre as marcas "--- 8< ---".
// Os valores abaixo sao so um exemplo e NAO funcionam com nenhuma placa real.
// ---------------------------------------------------------------------------

#define NO_SENSOR 1   // escolha um id unico por no (1..255)

static const uint8_t chaveNo[ASCON_SECURE_KEY_BYTES] = {
  0x3f, 0x8a, 0x1c, 0x09, 0xb4, 0xe7, 0x2d, 0x56,
  0x01, 0xfa, 0x88, 0x37, 0xcc, 0x90, 0xe1, 0xb2
};

static const uint8_t prefixoNo[ASCON_SECURE_PREFIX_BYTES] = {
  0x7d, 0x12, 0xee, 0x44, 0x09, 0xab, 0x63, 0xc0,
  0xf5, 0x8b, 0x1a, 0x22
};

void setup()
{
  Serial.begin(115200);
  asconSecureLogTo(Serial);
  asconSecureReceiverBegin();
  asconSecureAddPeer(NO_SENSOR, chaveNo, prefixoNo);

  // ---- LoRa: inicialize o radio aqui ----
}

void loop()
{
  // `pacote` e `tamanho` sao do RADIO, nao da seguranca: no seu sketch use o
  // buffer e o tamanho que a sua biblioteca de radio ja entrega. Aqui ficam
  // vazios so para o exemplo compilar -- com tamanho 0, o Open nao faz nada.
  uint8_t pacote[ASCON_SECURE_MAX_PACKET];
  size_t  tamanho = 0;   // ---- LoRa: ex. tamanho = radio.receber(pacote, sizeof(pacote)); ----

  AsconMessage leitura = asconSecureOpen(NO_SENSOR, pacote, tamanho);

  if (leitura) {
    Serial.write(leitura.data, leitura.length);
    Serial.println();
  }
}
