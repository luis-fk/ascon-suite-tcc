// A bateria roda uma vez para cada FORMATO de pacote. O Ascon-128a processa em
// blocos de 16 bytes, e e nas fronteiras de bloco que erros de implementacao
// aparecem: bloco vazio, parcial, exato, bloco+1 e multiplos blocos.
//
// Formatos diferentes geram informacao nova a cada volta. Repetir o mesmo
// formato nao geraria: o teste e determinista, mesma entrada da mesma resposta.

#ifndef AEAD_VECTORS_H
#define AEAD_VECTORS_H

#include <Arduino.h>

#define MAX_PLAINTEXT 32
#define MAX_AD        32
#define MAX_BUFFER    64   // maior pacote (32 + 16 de tag) mais folga
#define SENTINEL      0xA5 // preenche o buffer de saida antes de cada decifragem
#define LEAK_RUN      4    // sequencia que define o veredito de vazamento

struct PacketShape {
  const char *name;
  size_t      plaintextLength;
  size_t      associatedDataLength;
};

extern const PacketShape packetShapes[];
extern const int         packetShapeCount;

extern const uint8_t key[16];
extern const uint8_t nonce[16];

// Conteudo do formato em uso, reescrito a cada aeadBuildValidPacket().
extern uint8_t plaintext[MAX_PLAINTEXT];
extern uint8_t associatedData[MAX_AD];
extern size_t  plaintextLength;
extern size_t  associatedDataLength;

// Pacote valido (ciphertext || tag) do formato em uso.
extern uint8_t validCiphertext[MAX_BUFFER];
extern size_t  ciphertextLength;

// Monta o pacote do formato indicado e confere, como controle, que ele volta a
// ser decifrado corretamente. Devolve false se o controle falhar.
bool aeadBuildValidPacket(const PacketShape *shape);

#endif
