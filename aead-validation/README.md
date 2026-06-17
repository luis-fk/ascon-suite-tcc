# Validação AEAD (bit-flipping) — Ascon-128a (ESP32)

Sketch Arduino que valida a **autenticidade** do modo AEAD e sua capacidade de
**rejeitar adulterações** (Seção 3.4.2). Simula um ataque de *Man-in-the-middle*
por injeção de falhas (*bit-flipping*) sobre um pacote em trânsito.

## O que ele faz

1. Gera um pacote válido com a própria biblioteca (texto claro = payload do
   sensor; dados associados = cabeçalho LoRaWAN).
2. **Controle:** decifra o pacote intacto e confirma que ele é aceito e o texto
   claro é recuperado.
3. **Adulteração:** vira **cada bit** das três frentes previstas na metodologia
   — texto cifrado, dados associados (AD) e *tag* de autenticação — e confirma
   que **toda** modificação faz a decifragem falhar (`retorno < 0`), sem entregar
   texto claro adulterado.

Optamos por testar **todos os bits** de cada frente (e não apenas um), o que é
barato no ESP32 (algumas centenas de decifragens em milissegundos) e produz um
resultado mais forte: nenhuma alteração de 1 bit passa despercebida.

## Como rodar

1. Instalar a biblioteca `ascon-suite` no Arduino IDE.
2. Selecionar a placa ESP32 e a porta serial.
3. Compilar e gravar `Ascon128a_AEAD_BitFlip/Ascon128a_AEAD_BitFlip.ino`.
4. Abrir o Monitor Serial em **115200**.

Saída esperada: o controle `ACEITO`, cada frente com `N/N rejeitados` e, ao
final, `>>> AEAD OK: pacote intacto aceito, toda adulteracao rejeitada <<<`.

## Resultado

Na placa, o pacote intacto foi aceito (texto claro recuperado) e **todas as 560
adulterações de 1 bit foram rejeitadas**: 224/224 no texto cifrado, 208/208 nos
dados associados e 128/128 na *tag*. Nenhuma modificação passou despercebida. O
log da execução está em `aead-results.log`.

## Créditos

Usa a API `ascon128a_aead_encrypt/decrypt` da biblioteca ascon-suite (Rhys
Weatherley / Southern Storm Software, licença MIT). O sketch de teste e o
pacote de exemplo são de nossa autoria.
