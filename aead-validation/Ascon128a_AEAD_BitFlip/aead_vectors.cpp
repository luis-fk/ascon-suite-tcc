#include "aead_vectors.h"

#include <ASCON.h>
#include <string.h>

extern const uint8_t key[16] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

extern const uint8_t nonce[16] = {
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

// Textos de origem. Cada formato usa um prefixo destes, do tamanho que precisar.
// Sao bytes ASCII variados, para que a busca por vazamento tenha o que achar.
static const char PLAINTEXT_SOURCE[] = "temp=23.5C;lux=00812;batt=98;rssi=-71dBm";
static const char AD_SOURCE[]        = "devEUI=42fb8334;fcnt=00128;port=2;adr=1";

// Fronteiras de bloco do Ascon-128a (16 B), com e sem dados associados.
const PacketShape packetShapes[] = {
  { "PT=0  AD=26", 0,  26 },  // so a tag protege
  { "PT=5  AD=0",  5,   0 },  // bloco parcial, sem AD
  { "PT=16 AD=16", 16, 16 },  // bloco exato
  { "PT=17 AD=16", 17, 16 },  // bloco + 1
  { "PT=28 AD=26", 28, 26 },  // formato original, mantem comparabilidade
  { "PT=32 AD=32", 32, 32 },  // multiplos blocos dos dois lados
};

const int packetShapeCount = sizeof(packetShapes) / sizeof(packetShapes[0]);

uint8_t plaintext[MAX_PLAINTEXT];
uint8_t associatedData[MAX_AD];
size_t  plaintextLength      = 0;
size_t  associatedDataLength = 0;

uint8_t validCiphertext[MAX_BUFFER];
size_t  ciphertextLength = 0;

bool aeadBuildValidPacket(const PacketShape *shape)
{
  plaintextLength      = shape->plaintextLength;
  associatedDataLength = shape->associatedDataLength;

  memcpy(plaintext,      PLAINTEXT_SOURCE, plaintextLength);
  memcpy(associatedData, AD_SOURCE,        associatedDataLength);

  ascon128a_aead_encrypt(validCiphertext, &ciphertextLength,
                         plaintext, plaintextLength,
                         associatedData, associatedDataLength,
                         nonce, key);

  // Controle: o pacote intacto tem de ser aceito e devolver o texto original.
  uint8_t decryptOutput[MAX_BUFFER];
  size_t  messageLength = 0;

  int decryptResult = ascon128a_aead_decrypt(decryptOutput, &messageLength,
                                             validCiphertext, ciphertextLength,
                                             associatedData, associatedDataLength,
                                             nonce, key);

  return (decryptResult >= 0) &&
         (messageLength == plaintextLength) &&
         (plaintextLength == 0 ||
          memcmp(decryptOutput, plaintext, plaintextLength) == 0);
}
