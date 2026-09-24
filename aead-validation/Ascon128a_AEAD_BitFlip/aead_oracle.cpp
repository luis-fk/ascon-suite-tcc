#include "aead_oracle.h"
#include "aead_vectors.h"

#include <ASCON.h>
#include <string.h>

Result resultEmpty()
{
  Result result = {0, 0, 0, 0, 0, 0};
  return result;
}

void resultAdd(Result *total, Result part)
{
  total->tested   += part.tested;
  total->rejected += part.rejected;
  total->leaked2  += part.leaked2;
  total->leaked3  += part.leaked3;
  total->leaked4  += part.leaked4;

  if (part.maxRun > total->maxRun) {
    total->maxRun = part.maxRun;
  }
}

//
// Desliza de 1 em 1 nos dois lados: um vazamento pode comecar em qualquer
// deslocamento, e janelas coladas perderiam o que comeca no meio de uma delas.
static int longestPlaintextRun(const uint8_t *output, size_t outputLength)
{
  int longest = 0;

  for (size_t outputIndex = 0; outputIndex < outputLength; outputIndex++) {
    for (size_t plainIndex = 0; plainIndex < plaintextLength; plainIndex++) {

      size_t run = 0;
      while (outputIndex + run < outputLength &&
             plainIndex  + run < plaintextLength &&
             output[outputIndex + run] == plaintext[plainIndex + run]) {
        run++;
      }

      if ((int) run > longest) {
        longest = (int) run;
      }
    }
  }

  return longest;
}

void aeadCheckTampered(const uint8_t *packet, size_t packetLength,
                       const uint8_t *associated, size_t associatedLength,
                       const uint8_t *nonceToUse,
                       Result *result)
{
  uint8_t decryptOutput[MAX_BUFFER];
  size_t  messageLength = 0;

  // Preenche com SENTINEL para que qualquer escrita da biblioteca fique visivel.
  memset(decryptOutput, SENTINEL, sizeof(decryptOutput));

  int decryptResult = ascon128a_aead_decrypt(decryptOutput, &messageLength,
                                             packet, packetLength,
                                             associated, associatedLength,
                                             nonceToUse, key);

  result->tested++;

  if (decryptResult >= 0) {
    return;   // nao recusou: contabilizado como falha pelo total de rejeicoes
  }

  result->rejected++;

  size_t inspectLength = (messageLength > 0 && messageLength <= MAX_BUFFER)
                       ? messageLength
                       : MAX_BUFFER;

  int run = longestPlaintextRun(decryptOutput, inspectLength);

  if (run >= 2)        { result->leaked2++; }
  if (run >= 3)        { result->leaked3++; }
  if (run >= LEAK_RUN) { result->leaked4++; }

  if (run > result->maxRun) {
    result->maxRun = run;
  }
}

void printResult(const char *label, Result result)
{
  Serial.print("  ");
  Serial.print(label);
  Serial.print(" : ");
  Serial.print(result.rejected); Serial.print("/"); Serial.print(result.tested);
  Serial.print(" rejeitados");

  if (result.maxRun >= 2) {
    Serial.print("   | maior sequencia: ");
    Serial.print(result.maxRun);
    Serial.print(" B  (>=2: "); Serial.print(result.leaked2);
    Serial.print(", >=3: ");    Serial.print(result.leaked3);
    Serial.print(", >=4: ");    Serial.print(result.leaked4);
    Serial.print(")");
  }

  Serial.println();
}
