# AsconSecure — camada de segurança Ascon-128a para LoRa no ESP32

Biblioteca Arduino que cifra e autentica o *payload* de cada mensagem LoRa com
o Ascon-128a e rejeita repetições no receptor. Ela não fala com o rádio: recebe
bytes do sketch e devolve bytes para o sketch, nos dois sentidos. O rádio, o
cabeçalho do quadro e a configuração do enlace ficam com quem integra.

**Estado (27/09/2026):** compilada e testada em host; execução nas placas
ainda pendente.

## O pacote no ar

```
[ contador 4 B ][ texto cifrado (mesmo tamanho do payload) ][ tag 16 B ]
```

- Custo fixo de **20 bytes** por mensagem (`ASCON_SECURE_OVERHEAD`).
- O tamanho é o do *payload* de cada mensagem, sem preenchimento. O único
  limite é o teto `ASCON_SECURE_MAX_PAYLOAD` em `AsconSecure.h` (hoje 200,
  provisório; será ajustado ao teto do enlace). Acima dele o `Pack` devolve
  erro e nada vai ao ar.
- O *nonce* de 16 bytes é `prefixo (12 B, fixo por nó) || contador (4 B)`. Só o
  contador viaja; o receptor conhece o prefixo desde o provisionamento. O
  contador não precisa de proteção própria: alterá-lo altera o *nonce* e a
  *tag* falha.
- Não há cabeçalho da biblioteca. Se o enlace tiver um cabeçalho próprio em
  claro, ele fica fora deste pacote e pode ser autenticado pela *tag* como
  dado associado (ver `Wrap`/`Unwrap`).

## Fluxo de uso

1. **Provisionamento**, uma vez por nó sensor, na bancada
   (`examples/Provisionamento`). A placa gera a própria chave e o prefixo,
   grava na NVS e imprime na serial o bloco que vai no receptor. A chave nunca
   sai da placa por outro caminho. Rodar de novo só reimprime a chave existente;
   `asconSecureFactoryReset()` descarta tudo e gera outra.
2. **Emissor**, o nó sensor (`examples/Emissor`). `asconSecureBegin()` carrega a
   chave da NVS. Numa placa sem provisionamento ele devolve
   `ASCON_SECURE_ERR_NOT_PROVISIONED` em vez de inventar uma chave.
3. **Receptor**, o gateway (`examples/Receptor`). `asconSecureReceiverBegin()` e
   um `asconSecureAddPeer(id, chave, prefixo)` por nó, com o bloco colado do
   provisionamento. Até 8 nós (`MAX_PEERS`).

Chame o provisionamento antes de iniciar ADC, Wi-Fi ou Bluetooth: a geração da
chave usa o SAR ADC como fonte de entropia (`bootloader_random_enable()`), e o
ESP-IDF não permite usá-lo junto com esses periféricos.

## API

Atalhos, o jeito recomendado:

```cpp
AsconPacket pacote = asconSecurePack("temp=23.5C");       // ou (ptr, tamanho)
if (pacote) radio.transmit(pacote.data, pacote.length);

AsconMessage leitura = asconSecureOpen(NO_SENSOR, buf, tamanhoRecebido);
if (leitura) Serial.write(leitura.data, leitura.length); // já terminada em NUL
```

`if (resultado)` só é verdadeiro quando deu certo. Em qualquer falha `length`
vale 0 e `data` vem zerado, então não há como usar bytes errados por engano.
`asconSecureLogTo(Serial)` faz a biblioteca explicar na serial por que algo
foi recusado. Tamanho 0 no `Open` significa "nada chegou" e não é erro.

Camada crua, quando se quer autenticar um cabeçalho externo como dado
associado (o mesmo cabeçalho tem de ser passado dos dois lados):

```cpp
asconSecureWrap(payload, n, header, h, packet, cap, &packetLen);
asconSecureUnwrap(peerId, packet, packetLen, header, h, payload, cap, &payloadLen);
```

Códigos de retorno em `AsconSecureStatus`; `asconSecureStatusText()` dá o
texto. Os principais: `ERR_AUTH` (*tag* inválida ou pacote alterado),
`ERR_REPLAY` (contador já aceito), `ERR_BUFFER` (tamanho fora do limite),
`ERR_PEER` (nó não registrado), `ERR_NVS`, `ERR_NOT_PROVISIONED`.

## O que ela garante

- **Confidencialidade e integridade** do *payload* (AEAD). Qualquer alteração
  no texto cifrado, no contador, no cabeçalho autenticado ou na *tag* é
  rejeitada, e nenhum byte de texto claro chega ao sketch (validado em
  [`aead-validation/`](../aead-validation/), 4.907 adulterações).
- **Nonce nunca repetido**, mesmo com quedas de energia: o emissor grava na
  NVS uma reserva 32 valores à frente do contador antes de usá-los, e recomeça
  da reserva ao ligar. Uma queda joga fora até 32 valores, nunca repete um.
  Perto de 2^32 mensagens o `Pack` passa a devolver `ERR_EXHAUSTED`, e o nó
  precisa de novo provisionamento.
- **Anti-replay** no receptor: cada mensagem aceita grava o contador na NVS
  antes de ser entregue, e contadores iguais ou menores são recusados. A *tag*
  é verificada antes do teste de replay, para que um pacote forjado não consiga
  travar o contador do nó legítimo.
- **Sem alocação dinâmica** na cifragem e na decifragem, *buffers* de tamanho
  fixo (medido em [`benchmark-validation/`](../benchmark-validation/)). A NVS
  aloca e libera internamente a cada gravação, fora da cifragem.

## Limites conhecidos

- O provisionamento imprime a chave na serial. Só na bancada, com o nó em mãos.
- O registro anti-replay vive na NVS do gateway. Se ela for apagada, mensagens
  antigas voltam a ser aceitas até o contador ultrapassar o último valor.
- Renovar a chave é reprovisionar (`FactoryReset` no nó, bloco novo no
  receptor). Não há troca de chaves no ar.
- "Erase All Flash Before Sketch Upload" na IDE apaga a chave do nó.

## Instalação

Copie esta pasta para `Arduino/libraries/AsconSecure` e a raiz deste
repositório (a biblioteca `ASCON`, de que ela depende) para
`Arduino/libraries/ASCON`. Alvo: ESP32 e ESP32-S3, core arduino-esp32 3.x.
