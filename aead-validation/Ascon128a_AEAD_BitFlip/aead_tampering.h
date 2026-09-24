// As adulteracoes. Cada funcao devolve um Result com o total aplicado, o total
// recusado e o tamanho do maior fragmento de texto claro deixado na saida.
//
// Todas sao EXAUSTIVAS e deterministas: percorrem posicoes fixas, sem sorteio.
// Rodar duas vezes, ou rodar em duas placas, da exatamente o mesmo resultado.
//
// Grupo A -- inversao de 1 bit, a forma mais fraca de adulteracao, aplicada a
// cada bit das quatro frentes expostas a um interceptador.
//
// Grupo B -- formatos que 1 bit nao alcanca: dois bits, um byte inteiro, byte
// apagado, bytes distantes, corte, acrescimo e reordenacao. Existem para
// sustentar a afirmacao de que "qualquer modificacao" e detectada, que a
// varredura de 1 bit sozinha nao autoriza.

#ifndef AEAD_TAMPERING_H
#define AEAD_TAMPERING_H

#include "aead_oracle.h"

// --- Grupo A: 1 bit ---
Result flipCiphertextRegion(size_t rangeStart, size_t rangeEnd);
Result flipAssociatedData();
Result flipNonce();

// --- Grupo B: alem de 1 bit ---
Result flipAdjacentBitPairs();   // 2 bits juntos: (0,1), (2,3), (4,5), (6,7)
Result flipWholeByte();          // 8 bits de uma vez: XOR 0xFF
Result zeroByte();               // troca o byte por 0x00, em vez de inverter
Result flipTwoDistantBytes();    // 1 bit em dois bytes afastados
Result truncatePacket();         // corta bytes do fim
Result extendPacket();           // acrescenta bytes ao fim
Result swapAdjacentBytes();      // reordena sem alterar conteudo

#endif
