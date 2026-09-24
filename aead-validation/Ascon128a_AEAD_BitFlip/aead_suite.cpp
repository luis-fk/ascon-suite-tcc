#include "aead_suite.h"
#include "aead_tampering.h"
#include "aead_vectors.h"

#include <Arduino.h>

// Grupo A: cada bit de cada frente exposta ao interceptador.
static void runSingleBitGroup(Result *total)
{
  Serial.println("  [A] Inversao de 1 bit:");

  Result ciphertextResult = flipCiphertextRegion(0, plaintextLength);
  printResult("Ciphertext", ciphertextResult);
  resultAdd(total, ciphertextResult);

  Result associatedDataResult = flipAssociatedData();
  printResult("AD        ", associatedDataResult);
  resultAdd(total, associatedDataResult);

  Result tagResult = flipCiphertextRegion(plaintextLength, ciphertextLength);
  printResult("Tag       ", tagResult);
  resultAdd(total, tagResult);

  Result nonceResult = flipNonce();
  printResult("Nonce     ", nonceResult);
  resultAdd(total, nonceResult);
}

// Grupo B: o que a inversao de 1 bit nao alcanca.
static void runStructuralGroup(Result *total)
{
  Serial.println("  [B] Alem de 1 bit:");

  Result pairResult = flipAdjacentBitPairs();
  printResult("2 bits    ", pairResult);
  resultAdd(total, pairResult);

  Result byteResult = flipWholeByte();
  printResult("Byte (8b) ", byteResult);
  resultAdd(total, byteResult);

  Result zeroResult = zeroByte();
  printResult("Byte zero ", zeroResult);
  resultAdd(total, zeroResult);

  Result distantResult = flipTwoDistantBytes();
  printResult("2 distant ", distantResult);
  resultAdd(total, distantResult);

  Result truncateResult = truncatePacket();
  printResult("Truncado  ", truncateResult);
  resultAdd(total, truncateResult);

  Result extendResult = extendPacket();
  printResult("Estendido ", extendResult);
  resultAdd(total, extendResult);

  Result swapResult = swapAdjacentBytes();
  printResult("Reordenado", swapResult);
  resultAdd(total, swapResult);
}

static void printShapeHeader(const PacketShape *shape, bool controlPassed)
{
  Serial.println();
  Serial.print("--- ");
  Serial.print(shape->name);
  Serial.print("  ->  pacote de ");
  Serial.print((unsigned) ciphertextLength);
  Serial.print(" B  |  controle: ");
  Serial.println(controlPassed ? "ACEITO" : "FALHOU (inesperado)");
}

static void printShapeTotal(Result shapeTotal)
{
  Serial.print("      subtotal: ");
  Serial.print(shapeTotal.rejected); Serial.print("/"); Serial.print(shapeTotal.tested);
  Serial.print(" rejeitados, maior sequencia ");
  Serial.print(shapeTotal.maxRun);
  Serial.println(" B");
}

static void printGrandSummary(int controlFailures, Result total)
{
  Serial.println();
  Serial.println("===============================================================");
  Serial.print("Formatos testados : "); Serial.println(packetShapeCount);
  Serial.print("Controles aceitos : ");
  Serial.print(packetShapeCount - controlFailures);
  Serial.print("/"); Serial.println(packetShapeCount);
  Serial.print("Adulteracoes      : ");
  Serial.print(total.rejected); Serial.print("/"); Serial.print(total.tested);
  Serial.println(" rejeitadas");

  Serial.println();
  Serial.println("Fragmentos do texto claro deixados no buffer de saida:");
  Serial.print("  maior sequencia encontrada : ");
  Serial.print(total.maxRun); Serial.println(" byte(s)");
  Serial.print("  casos com >= 2 bytes       : "); Serial.println(total.leaked2);
  Serial.print("  casos com >= 3 bytes       : "); Serial.println(total.leaked3);
  Serial.print("  casos com >= 4 bytes       : "); Serial.println(total.leaked4);

  if (total.leaked2 > 0 && total.leaked4 == 0) {
    Serial.println("  (sequencias de 2 a 3 bytes isoladas sao coincidencia esperada,");
    Serial.println("   nao vazamento; ver o README)");
  }

  Serial.println();

  if (controlFailures == 0 && total.rejected == total.tested && total.leaked4 == 0) {
    Serial.println(">>> AEAD OK: intacto aceito, toda adulteracao rejeitada, nenhum vazamento <<<");
  }
  else {
    Serial.println(">>> FALHA: ver acima <<<");
  }

  // Limite conhecido, registrado no log para deixar claro o que NAO foi testado.
  Serial.println();
  Serial.println("Nota: a repeticao (replay) de um pacote intacto NAO e detectavel pelo");
  Serial.println("AEAD; depende de verificacao de frescor do nonce no receptor.");
}

void aeadSuiteRun()
{
  Serial.println();
  Serial.println("=== Ascon-128a AEAD: rejeicao de adulteracao (Secao 3.4.2) ===");
  Serial.println("Bateria exaustiva e determinista, repetida por formato de pacote.");

  Result grandTotal     = resultEmpty();
  int    controlFailures = 0;

  for (int shapeIndex = 0; shapeIndex < packetShapeCount; shapeIndex++) {
    const PacketShape *shape = &packetShapes[shapeIndex];

    bool controlPassed = aeadBuildValidPacket(shape);

    if (!controlPassed) {
      controlFailures++;
    }

    printShapeHeader(shape, controlPassed);

    Result shapeTotal = resultEmpty();
    runSingleBitGroup(&shapeTotal);
    runStructuralGroup(&shapeTotal);
    printShapeTotal(shapeTotal);

    resultAdd(&grandTotal, shapeTotal);
  }

  printGrandSummary(controlFailures, grandTotal);
}
