#include "aead_tampering.h"
#include "aead_vectors.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Grupo A: inversao de 1 bit.
// ---------------------------------------------------------------------------

Result flipCiphertextRegion(size_t rangeStart, size_t rangeEnd)
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = rangeStart; byteIndex < rangeEnd; byteIndex++) {
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      memcpy(tampered, validCiphertext, ciphertextLength);
      tampered[byteIndex] ^= (uint8_t)(1 << bitIndex);

      aeadCheckTampered(tampered, ciphertextLength,
                        associatedData, associatedDataLength, nonce, &result);
    }
  }

  return result;
}

Result flipAssociatedData()
{
  Result result = resultEmpty();
  uint8_t tamperedAssociatedData[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex < associatedDataLength; byteIndex++) {
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      memcpy(tamperedAssociatedData, associatedData, associatedDataLength);
      tamperedAssociatedData[byteIndex] ^= (uint8_t)(1 << bitIndex);

      aeadCheckTampered(validCiphertext, ciphertextLength,
                        tamperedAssociatedData, associatedDataLength, nonce, &result);
    }
  }

  return result;
}

// Num pacote real o nonce viaja em claro junto da mensagem, portanto tambem
// esta ao alcance de um interceptador.
Result flipNonce()
{
  Result result = resultEmpty();
  uint8_t tamperedNonce[16];

  for (size_t byteIndex = 0; byteIndex < sizeof(tamperedNonce); byteIndex++) {
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      memcpy(tamperedNonce, nonce, sizeof(tamperedNonce));
      tamperedNonce[byteIndex] ^= (uint8_t)(1 << bitIndex);

      aeadCheckTampered(validCiphertext, ciphertextLength,
                        associatedData, associatedDataLength, tamperedNonce, &result);
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Grupo B: alem de 1 bit.
// ---------------------------------------------------------------------------

// Dois bits vizinhos, em todos os pares de cada byte: (0,1), (2,3), (4,5), (6,7).
Result flipAdjacentBitPairs()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex < ciphertextLength; byteIndex++) {
    for (int firstBit = 0; firstBit < 8; firstBit += 2) {
      memcpy(tampered, validCiphertext, ciphertextLength);
      tampered[byteIndex] ^= (uint8_t)((1 << firstBit) | (1 << (firstBit + 1)));

      aeadCheckTampered(tampered, ciphertextLength,
                        associatedData, associatedDataLength, nonce, &result);
    }
  }

  return result;
}

// Os oito bits de um byte de uma so vez.
Result flipWholeByte()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex < ciphertextLength; byteIndex++) {
    memcpy(tampered, validCiphertext, ciphertextLength);
    tampered[byteIndex] ^= 0xFF;

    aeadCheckTampered(tampered, ciphertextLength,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}

// Apaga o byte em vez de inverte-lo: substituicao, nao inversao.
// Bytes que ja valem zero sao pulados, pois apaga-los nao muda nada e o pacote
// seria legitimamente aceito.
Result zeroByte()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex < ciphertextLength; byteIndex++) {
    if (validCiphertext[byteIndex] == 0x00) {
      continue;
    }

    memcpy(tampered, validCiphertext, ciphertextLength);
    tampered[byteIndex] = 0x00;

    aeadCheckTampered(tampered, ciphertextLength,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}

// Um bit em dois bytes afastados: cobre adulteracao espalhada pelo pacote,
// e nao so concentrada num ponto.
Result flipTwoDistantBytes()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];
  size_t  offset = ciphertextLength / 2;

  for (size_t byteIndex = 0; byteIndex < offset; byteIndex++) {
    memcpy(tampered, validCiphertext, ciphertextLength);
    tampered[byteIndex]          ^= 0x01;
    tampered[byteIndex + offset] ^= 0x80;

    aeadCheckTampered(tampered, ciphertextLength,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}

// O atacante corta bytes do fim do pacote.
Result truncatePacket()
{
  Result result = resultEmpty();

  for (size_t truncatedLength = 1; truncatedLength < ciphertextLength; truncatedLength++) {
    aeadCheckTampered(validCiphertext, truncatedLength,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}

// O atacante acrescenta bytes ao fim do pacote.
Result extendPacket()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (int extraByte = 0; extraByte < 4; extraByte++) {
    memcpy(tampered, validCiphertext, ciphertextLength);
    tampered[ciphertextLength] = (uint8_t)(extraByte * 0x55);

    aeadCheckTampered(tampered, ciphertextLength + 1,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}

// Troca bytes adjacentes de lugar: reordenacao sem alterar o conteudo.
// Posicoes com bytes iguais sao puladas, pois a troca nao mudaria nada e o
// pacote seria legitimamente aceito.
Result swapAdjacentBytes()
{
  Result result = resultEmpty();
  uint8_t tampered[MAX_BUFFER];

  for (size_t byteIndex = 0; byteIndex + 1 < ciphertextLength; byteIndex++) {
    if (validCiphertext[byteIndex] == validCiphertext[byteIndex + 1]) {
      continue;
    }

    memcpy(tampered, validCiphertext, ciphertextLength);

    uint8_t swap            = tampered[byteIndex];
    tampered[byteIndex]     = tampered[byteIndex + 1];
    tampered[byteIndex + 1] = swap;

    aeadCheckTampered(tampered, ciphertextLength,
                      associatedData, associatedDataLength, nonce, &result);
  }

  return result;
}
