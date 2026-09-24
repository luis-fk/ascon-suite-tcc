# Validação AEAD (adulteração) — Ascon-128a (ESP32)

Sketch Arduino que valida a **autenticidade** do modo AEAD e sua capacidade de
**rejeitar adulterações** (Seção 3.4.2). Simula um ataque de *Man-in-the-middle*
sobre um pacote em trânsito, repetindo a bateria para seis formatos de pacote.

## O que ele faz

Para cada formato de pacote:

1. Gera um pacote válido com a própria biblioteca (texto claro = payload do
   sensor; dados associados = cabeçalho LoRaWAN).
2. **Controle:** decifra o pacote intacto e confirma que ele é aceito e o texto
   claro é recuperado.
3. **Adulteração:** modifica o pacote de onze maneiras diferentes (quatro de
   1 bit, sete estruturais) e confirma que **toda** modificação faz a
   decifragem falhar (`retorno < 0`).
4. **Vazamento:** a cada recusa, verifica se sobrou texto claro no buffer de
   saída.

## Formatos de pacote

O Ascon-128a processa blocos de 16 bytes. Erros de implementação costumam
aparecer nas fronteiras de bloco, então os formatos foram escolhidos para
cobri-las, com e sem dados associados:

| Formato | Texto claro | AD | Pacote (texto cifrado + tag) | Por quê |
|---|---|---|---|---|
| `PT=0  AD=26` | 0 B | 26 B | 16 B | só a tag protege |
| `PT=5  AD=0` | 5 B | 0 B | 21 B | bloco parcial, sem AD |
| `PT=16 AD=16` | 16 B | 16 B | 32 B | bloco exato |
| `PT=17 AD=16` | 17 B | 16 B | 33 B | bloco + 1 |
| `PT=28 AD=26` | 28 B | 26 B | 44 B | formato original do teste |
| `PT=32 AD=32` | 32 B | 32 B | 48 B | múltiplos blocos dos dois lados |

Todos usam um prefixo dos mesmos dois textos de origem (`temp=23.5C;lux=…` e
`devEUI=42fb8334;fcnt=…`), cortado no tamanho do formato. Não há vários textos
claros: há um texto e vários tamanhos.

### Grupo A — inversão de 1 bit

Vira **cada bit** das quatro frentes expostas a um interceptador. *Tag* e
*nonce* têm sempre 128 bits; texto cifrado e AD têm 8 bits por byte do formato.

| Frente | Bits testados |
|---|---|
| Texto cifrado | 8 × tamanho do texto claro |
| Dados associados (AD) | 8 × tamanho do AD |
| *Tag* de autenticação | 128 |
| *Nonce* | 128 |

O *nonce* entra porque, num pacote real, ele viaja em claro junto da mensagem —
é assim que o destinatário consegue decifrar.

### Grupo B — o que 1 bit não alcança

Inverter um bit é a forma mais fraca de adulteração. Para sustentar a afirmação
de que *qualquer* modificação é detectada, o grupo B cobre outros formatos,
todos aplicados sobre o pacote (texto cifrado + tag):

| Adulteração | O que faz |
|---|---|
| 2 bits | vira os pares `(0,1)`, `(2,3)`, `(4,5)`, `(6,7)` de cada byte |
| Byte (8b) | vira os 8 bits de um byte de uma vez (`XOR 0xFF`) |
| Byte zero | apaga o byte, em vez de invertê-lo |
| 2 distantes | 1 bit no byte `i` e 1 bit no byte `i + metade do pacote` |
| Truncado | corta o pacote em cada tamanho possível, de 1 byte até o original menos 1 |
| Estendido | acrescenta 1 byte ao fim, com quatro valores (`0x00`, `0x55`, `0xAA`, `0xFF`) |
| Reordenado | troca bytes vizinhos de lugar |

**Todas são exaustivas e deterministas** — percorrem posições fixas, sem
sorteio. Rodar duas vezes, ou rodar em placas diferentes, dá exatamente o mesmo
resultado. `Byte zero` e `Reordenado` pulam os casos em que a operação não
mudaria nada (byte já nulo, vizinhos iguais), pois aí o pacote continuaria
legitimamente válido.

## Verificação de vazamento

A metodologia promete mais do que um código de erro: promete que *"nenhum
fragmento do texto claro modificado seja entregue à camada de aplicação"*.
Conferir só o retorno da função não testa isso.

Então, antes de cada decifragem, o buffer de saída é preenchido com `0xA5` — um
valor que não é ASCII e portanto nunca coincide com o texto claro. Depois de uma
recusa, o sketch mede a **maior sequência de bytes** presente ao mesmo tempo na
saída e no texto claro original, e reporta quantos casos atingiram 2, 3 e 4
bytes.

Como ler:

| Maior sequência | Leitura |
|---|---|
| 0 | nada escrito que se pareça com o texto claro |
| 1 | ruído, ignorar |
| 2 | provável acaso, sobretudo se forem poucos casos |
| 3 ou mais | **achado real** — vazamento é contíguo, acaso é curto e disperso |

O veredito final usa o limiar de 4 bytes (`LEAK_RUN`).

## Organização dos arquivos

| Arquivo | Responsabilidade |
|---|---|
| `Ascon128a_AEAD_BitFlip.ino` | apenas `setup()`/`loop()` |
| `aead_vectors.h/.cpp` | formatos de pacote, entradas do teste e montagem do pacote válido |
| `aead_oracle.h/.cpp` | decide: recusou? vazou texto claro? |
| `aead_tampering.h/.cpp` | as adulterações |
| `aead_suite.h/.cpp` | orquestração e relatório |

A separação é por **pergunta**: o *oracle* julga e não sabe quais adulterações
existem; o *tampering* fabrica ataques e não sabe julgar. Adulteração nova
acrescentada ao *tampering* já ganha a verificação de vazamento de graça.

## Como rodar

O código é **o mesmo para o ESP32 clássico e para a placa Heltec** — o sketch
não usa rádio nem pinos específicos, só a serial e a biblioteca.

1. Instalar a biblioteca `ascon-suite` no Arduino IDE.
2. Abrir `Ascon128a_AEAD_BitFlip/Ascon128a_AEAD_BitFlip.ino` (os nove arquivos
   da pasta — `.ino`, `.h` e `.cpp` — são compilados juntos, automaticamente).
3. Escolher a placa em **Ferramentas → Placa**:
   - ESP32 clássico: *ESP32 Dev Module*
   - Heltec: *Heltec WiFi LoRa 32 V3* (ou *ESP32S3 Dev Module*)
4. Selecionar a porta e gravar.
5. Abrir o Monitor Serial em **115200**.

### Se a serial não mostrar nada na Heltec

A Heltec V3 é ESP32-S3 e usa USB nativo. Em **Ferramentas**, habilitar
**USB CDC On Boot**. Sem isso a placa grava normalmente, mas não aparece saída
no Monitor Serial.

## Resultado

Executado nas duas placas. As saídas estão em
`Ascon128a_AEAD_BitFlip/aead-results-esp32.txt` (ESP32 clássico) e
`Ascon128a_AEAD_BitFlip/aead-results-heltec.txt` (Heltec WiFi LoRa 32 V3,
ESP32-S3). Os dois arquivos diferem apenas nas linhas de boot do chip; do
início do teste em diante são **idênticos byte a byte**, como se espera de uma
bateria determinista.

| Formato | Pacote | Adulterações | Rejeitadas | Maior sequência vazada |
|---|---|---|---|---|
| `PT=0  AD=26` | 16 B | 602 | 602 | 0 B |
| `PT=5  AD=0` | 21 B | 476 | 476 | 0 B |
| `PT=16 AD=16` | 32 B | 786 | 786 | 0 B |
| `PT=17 AD=16` | 33 B | 802 | 802 | 0 B |
| `PT=28 AD=26` | 44 B | 1063 | 1063 | 0 B |
| `PT=32 AD=32` | 48 B | 1178 | 1178 | 0 B |
| **Total** | | **4907** | **4907** | **0 B** |

- Controles: 6/6 pacotes intactos aceitos, com o texto claro recuperado.
- Adulterações: 4907/4907 rejeitadas.
- Vazamento: nenhum caso com 2 ou mais bytes do texto claro no buffer de saída.

Veredito impresso pelo sketch:

```
>>> AEAD OK: intacto aceito, toda adulteracao rejeitada, nenhum vazamento <<<
```

A versão anterior deste sketch cobria apenas três frentes de 1 bit, num único
formato (560 adulterações), e não verificava vazamento. Os números antigos não
são comparáveis aos desta versão.

## Limite conhecido: *replay*

O AEAD **não** detecta repetição. Um pacote válido capturado e reenviado sem
alteração nenhuma passa em todos os testes acima, porque de fato não foi
adulterado. Detectar isso exige estado no receptor — lembrar o maior *nonce* já
visto e recusar o que for igual ou menor —, o que pertence à camada de
comunicação, não ao algoritmo. O sketch imprime essa ressalva ao final, para que
o log registre o que **não** foi testado.

## Créditos

Usa a API `ascon128a_aead_encrypt/decrypt` da biblioteca ascon-suite (Rhys
Weatherley / Southern Storm Software, licença MIT). O sketch de teste e o
pacote de exemplo são de nossa autoria.
