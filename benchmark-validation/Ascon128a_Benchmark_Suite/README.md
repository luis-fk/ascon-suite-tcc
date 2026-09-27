# Benchmark — memória, tempo e comparativo com AES-128-GCM (Ascon-128a, ESP32)

Sketch Arduino que mede, num único *firmware*, tudo o que a Seção 3.4.3 pede
para o Ascon-128a e o comparativo com o AES-128-GCM da Seção 5.2.4. Até
27/09/2026 isso estava espalhado em cinco sketches (`Ascon128a_Benchmark`,
`Ascon128a_Benchmark_Loop`, `AsconVsAES_Benchmark`, `AsconVsAES_Benchmark_Loop`
e `AES_HardwareCheck`), removidos quando esta suíte os substituiu. O histórico
do git os guarda.

Um firmware só porque quatro firmwares davam quatro pisos diferentes para a
mesma operação (6.117, 6.115, 6.114 e 6.111 ciclos), por diferença de geração
de código entre builds. Agora há um número por medida.

## O que ele faz, na ordem do log

| Seção | O que mede | Veredito |
|---|---|---|
| `[0]` Identificação | chip, ESP-IDF, core arduino-esp32, MHz, tamanho do sketch e da partição | — |
| `[1]` Autoteste | dois vetores oficiais do KAT (Count 529 e 545) e o Test Case 2 do GCM: cifra, decifra e recusa de *tag* adulterada. Se falhar, **nada é medido**. De brinde, o custo da primeira chamada de cada algoritmo com a *cache* fria | `AUTOTESTE FALHOU` para tudo |
| `[2]` Memória | *heap* livre antes e depois de cada operação, em cada tamanho, e o menor valor visto por um observador no outro núcleo durante a operação; pilha medida numa tarefa dedicada | alocação no Ascon é `PROBLEMA` |
| `[3]` Tempo do Ascon | cifra e decifra em 0, 2, 16, 23, 32 e 64 B; 100 execuções de 2.000 medidas; piso com interrupções desligadas como contraprova; modelo linear; parcela fixa medida e extrapolada; granularidade de bloco | piso não reproduzido é `RESSALVA` |
| `[4]` Tempo constante | cifragem em 16 e 64 B com cinco classes de entrada (rampa, zeros, uns, alternado, *hash*) | pisos ou médias divergentes é `RESSALVA` |
| `[5]` Comparativo | Ascon e AES-GCM alternados na mesma execução, cifra e decifra, 100 execuções por tamanho; razão por execução; contagem de vitórias | AES mais rápido em alguma execução é `RESSALVA` |
| `[6]` Decomposição | quatro macros do SDK (definida/ausente); AES-CTR; GHASH = GCM − CTR; régua do TRM (11–15 ciclos por bloco) | GHASH negativo é `PROBLEMA`; GHASH barato é `RESSALVA` |
| `[7]` Resumo | custo da mensagem típica de 23 B, custo por bloco, contagem de problemas e ressalvas | `BENCHMARK OK` ou `COM PROBLEMAS` |

`PROBLEMA` invalida o número afetado. `RESSALVA` é um achado que o texto tem
de mencionar. As duas contagens aparecem no fim.

## Regras de medição

- **Ciclos de CPU** lidos por `ESP.getCycleCount()`, com a chamada indireta por
  ponteiro de função (custo fixo de poucos ciclos, igual para todos).
- **Piso de 2.000 medidas** com interrupções **ligadas**, para todos, para que
  Ascon e AES sejam medidos do mesmo jeito. O driver de AES do ESP-IDF já
  protege a operação de bloco com uma seção crítica própria
  (`port/aes/block/esp_aes.c`, "AES uses a spinlock mux"); o piso filtra as
  interrupções que caem no resto da chamada. Para o Ascon, o piso com
  interrupções desligadas é impresso ao lado: se os dois coincidem, o piso é
  livre de ISR.
- **100 execuções** independentes por tamanho e operação. A métrica entre
  execuções é o piso de cada uma; a variação dentro de cada uma é reportada em
  separado. Não há "execução única": a tabela da tese é o piso reproduzido
  cem vezes.
- **Tamanhos 0, 2, 16, 23, 32 e 64 bytes.** O 0 mede a parcela fixa
  diretamente, em vez de extrapolá-la. O 2 e o 23 são os dois tamanhos que
  ocorrem no *dataset* Tour Perret, da frente de ML (91 % das mensagens têm
  23 B e 7 % têm 2 B). O 16, 32 e 64 são as fronteiras de bloco do modelo
  linear.
- **Cifra e decifra**, dos dois algoritmos. As decifragens medidas são de
  pacotes válidos; qualquer recusa durante a medição é contada e vira
  `PROBLEMA`, porque uma recusa é mais rápida que uma decifragem completa.
- **Chave do AES fixada uma vez por execução**, que é o caso real de um nó
  com uma chave. O custo do `setkey` fica fora da medição.
- **Dados associados vazios**, que é o formato da biblioteca `ascon-lora`.
- **Nada é sorteado.** Todas as entradas são deterministas: rodar duas vezes,
  ou em placas diferentes, mede as mesmas operações sobre os mesmos bytes.

### Granularidade de bloco, o que esperar

O Ascon-128a executa uma permutação por bloco **completo seguido de mais
dados**; o bloco final, cheio ou não, é apenas preenchido. Então 0 e 2 B custam
igual, 16 e 23 B custam igual, e 32 B é o próximo degrau. O AES-GCM cifra
`ceil(n/16)` blocos no CTR: 2 B custa como 16, 23 B custa como 32. A seção
`[3]` confere a regra do Ascon e a `[5]` mostra a do AES.

### Heap: por que um observador

Uma alocação feita e liberada dentro da operação não muda o *heap* livre de
antes nem o de depois. O "heap mínimo histórico" do ESP-IDF também não serve:
é a soma dos mínimos de cada região de memória, e uma alocação só deixa marca
se a região em que caiu descer abaixo do próprio mínimo, o que normalmente não
acontece. Então uma tarefa no núcleo 0 lê o *heap* livre em laço enquanto a
operação roda no núcleo 1 e guarda o menor valor. O log diz quantas leituras
houve; algumas dezenas em 40 µs bastam para pegar os descritores do driver de
DMA do ESP32-S3, que vivem quase a operação inteira.

### Pilha

`uxTaskGetStackHighWaterMark` devolve o ponto mais fundo que a pilha da tarefa
**já** atingiu. Lida na tarefa principal depois de `Serial.print`, não mede
nada. Por isso cada operação roda oito vezes numa tarefa nova de 8.192 bytes,
e a marca é lida lá dentro, antes e depois, sem imprimir nada no meio. No
ESP-IDF a marca vem em bytes (`task.h`: "in bytes not words, unlike vanilla
FreeRTOS").

## Organização dos arquivos

| Arquivo | Responsabilidade |
|---|---|
| `Ascon128a_Benchmark_Suite.ino` | apenas `setup()`/`loop()` |
| `bench_config.h` | tamanhos, `RUNS`, `ITERATIONS`, tolerâncias |
| `bench_board.h/.cpp` | identificação do build |
| `bench_inputs.h/.cpp` | buffers e as classes de entrada |
| `bench_timer.h/.cpp` | a primitiva de medição, única para Ascon e AES |
| `bench_ascon.h/.cpp` | operações do Ascon e autoteste com o KAT |
| `bench_aes.h/.cpp` | GCM, CTR, autoteste com o Test Case 2 e as quatro macros do SDK |
| `bench_memory.h/.cpp` | *heap* por operação e pilha em tarefa dedicada |
| `bench_report.h/.cpp` | linhas de resultado, ajuste linear, contagem de problemas |
| `bench_suite.h/.cpp` | as sete seções, na ordem, e o veredito |

A separação é por pergunta: o *timer* mede e não sabe o que mede; `ascon` e
`aes` dizem o que medir e não sabem medir; `suite` decide a ordem e julga.

## Como rodar

O código é o mesmo para o ESP32 clássico e para a Heltec WiFi LoRa 32 V3
(ESP32-S3): só a serial e as bibliotecas.

1. Instalar a biblioteca `ascon-suite` no Arduino IDE (a mbedTLS já vem no
   core do ESP32).
2. Abrir `Ascon128a_Benchmark_Suite.ino`; os arquivos da pasta compilam
   juntos.
3. Escolher a placa em **Ferramentas → Placa**: *ESP32 Dev Module* ou *Heltec
   WiFi LoRa 32 V3*. Na Heltec, habilitar **USB CDC On Boot** para a serial.
4. Gravar. Abrir o Monitor Serial em **115200**.
5. Esperar uns 7 minutos; cada `.` é uma execução. Salvar a saída inteira em
   `bench-results-esp32.txt` ou `bench-results-heltec.txt`, nesta pasta.

Régua de aceitação antes de aposentar os sketches antigos: no ESP32 clássico,
o custo por bloco tem de reproduzir 1.097 ciclos (Ascon) e 2.109 (AES-GCM), e
os pisos ficarem a poucos ciclos dos publicados na Seção 5.2.

## Resultado

Executado nas duas placas com o mesmo firmware: core arduino-esp32 3.3.11,
ESP-IDF 5.5.5, 240 MHz. Saídas em `bench-results-esp32.txt` (ESP32-D0WDQ6,
partição de 1.310.720 B) e `bench-results-heltec.txt` (ESP32-S3 rev 2,
partição de 3.342.336 B). Veredito `BENCHMARK OK` nas duas; zero problemas;
2 ressalvas no clássico e 7 na Heltec, todas listadas abaixo. As tabelas são
geradas por `parse_results.py` a partir dos logs.

Régua de aceitação: o clássico reproduziu os 1.097 (Ascon) e 2.109 (AES-GCM)
ciclos por bloco das medições anteriores, exatos, e os pisos a +17 e +62
ciclos, constantes em todos os tamanhos (build e chamada indireta).

### Como ler

- **Piso** é o menor de 2.000 medidas, reproduzido em 100 execuções. Onde o
  log diz "execuções no piso 100/100" e "spread 0", o número é determinista.
- **Razão** é AES-GCM sobre Ascon na mesma execução; maior que 1 é Ascon mais
  rápido.
- **µs** a 240 MHz.

## Cifra: piso em ciclos (µs), por tamanho

| Bytes | Ascon ESP32 clássico | AES-GCM ESP32 clássico | razão | Ascon Heltec (ESP32-S3) | AES-GCM Heltec (ESP32-S3) | razão |
|---|---|---|---|---|---|---|
| 0 | 5.037 (21.0) | 6.497 (27.1) | 1.29 | 4.603 (19.2) | 10.465 (43.6) | 2.27 |
| 2 | 5.181 (21.6) | 8.174 (34.1) | 1.58 | 4.722 (19.7) | 16.556 (69.0) | 3.51 |
| 16 | 6.134 (25.6) | 8.603 (35.8) | 1.40 | 5.639 (23.5) | 19.473 (81.1) | 3.45 |
| 23 | 6.521 (27.2) | 10.454 (43.6) | 1.60 | 5.960 (24.8) | 20.920 (87.2) | 3.51 |
| 32 | 7.231 (30.1) | 10.712 (44.6) | 1.48 | 6.675 (27.8) | 20.398 (85.0) | 3.06 |
| 64 | 9.425 (39.3) | 14.930 (62.2) | 1.58 | 8.747 (36.4) | 22.267 (92.8) | 2.55 |

### Decifra: piso em ciclos, por tamanho

| Bytes | Ascon ESP32 clássico | AES-GCM ESP32 clássico | razão | Ascon Heltec (ESP32-S3) | AES-GCM Heltec (ESP32-S3) | razão |
|---|---|---|---|---|---|---|
| 0 | 5.256 | 6.908 | 1.31 | 4.755 | 10.814 | 2.27 |
| 2 | 5.366 | 8.585 | 1.60 | 4.841 | 16.903 | 3.49 |
| 16 | 6.646 | 9.014 | 1.36 | 5.959 | 19.820 | 3.33 |
| 23 | 6.989 | 10.867 | 1.55 | 6.212 | 21.269 | 3.42 |
| 32 | 8.036 | 11.123 | 1.38 | 7.163 | 20.745 | 2.90 |
| 64 | 10.816 | 15.341 | 1.42 | 9.571 | 22.616 | 2.36 |

### Modelo linear e decomposição (ciclos por bloco de 16 B)

| | ESP32 clássico | Heltec (ESP32-S3) |
|---|---|---|
| Ascon cifra: parcela fixa | 5037 | 4603 |
| Ascon cifra: por bloco | 1097.0 | 1036.0 |
| Ascon decifra: parcela fixa | 5256 | 4755 |
| Ascon decifra: por bloco | 1390.0 | 1204.0 |
| AES-CTR por bloco | 825 | 49 |
| AES-CTR 16 B (custo total) | 2316 | 8218 |
| AES-GCM por bloco | 2109 | 931 |
| GHASH por bloco (GCM − CTR) | 1284 | 882 |
| Bloco parcial: 2−0 B / 23−16 B | 144 / 387 | 119 / 321 |
| AES-GCM 2−0 / 23−16 / 32−23 B | 1677 / 1851 / 258 | 6091 / 1447 / -522 |
| Ascon venceu | 1200/1200 | 1200/1200 |

### Memória

| | ESP32 clássico | Heltec (ESP32-S3) |
|---|---|---|
| Ascon-128a cifra | heap: sem alocação (≥76 amostras); pilha 340 B | heap: sem alocação (≥678 amostras); pilha 224 B |
| Ascon-128a decifra | heap: sem alocação (≥262 amostras); pilha 436 B | heap: sem alocação (≥598 amostras); pilha 436 B |
| AES-128-GCM cifra | heap: sem alocação (≥278 amostras); pilha 548 B | heap: transitória de 40 B (≥761 amostras); pilha 628 B |
| AES-128-GCM decifra | heap: sem alocação (≥281 amostras); pilha 628 B | heap: transitória de 40 B (≥690 amostras); pilha 804 B |

### Tempo constante (5 classes, interrupções desligadas)

- ESP32 clássico, 16 B: pisos 6135–6135 (spread 0), médias 6135.03–6135.04 (spread 0.01 ciclos)
- ESP32 clássico, 64 B: pisos 9426–9426 (spread 0), médias 9426.05–9426.06 (spread 0.02 ciclos)
  desvio dentro da execução (rampa): 0.23, 0.42 ciclos; máximo 6140, 9432
- Heltec (ESP32-S3), 16 B: pisos 5639–5639 (spread 0), médias 5642.31–5642.67 (spread 0.36 ciclos)
- Heltec (ESP32-S3), 64 B: pisos 8747–8747 (spread 0), médias 8752.07–8752.48 (spread 0.41 ciclos)
  desvio dentro da execução (rampa): 24.58, 26.03 ciclos; máximo 6181, 8899

### Primeira chamada (cache fria, 16 B)

- ESP32 clássico: Ascon-128a cifra 53.314 ciclos (222 µs); Ascon-128a decifra 18.222 ciclos (76 µs); AES-128-GCM cifra 38.983 ciclos (162 µs); AES-128-GCM decifra 10.639 ciclos (44 µs)
- Heltec (ESP32-S3): Ascon-128a cifra 52.127 ciclos (217 µs); Ascon-128a decifra 16.148 ciclos (67 µs); AES-128-GCM cifra 113.058 ciclos (471 µs); AES-128-GCM decifra 21.256 ciclos (89 µs)

### Macros

- ESP32 clássico: SOC_AES_SUPPORT_GCM ausente, SOC_AES_SUPPORT_DMA ausente, CONFIG_MBEDTLS_HARDWARE_AES definida, CONFIG_MBEDTLS_HARDWARE_GCM ausente
- Heltec (ESP32-S3): SOC_AES_SUPPORT_GCM ausente, SOC_AES_SUPPORT_DMA definida, CONFIG_MBEDTLS_HARDWARE_AES definida, CONFIG_MBEDTLS_HARDWARE_GCM ausente

### Ressalvas registradas

- **AES-GCM aloca na Heltec**: 40 bytes transitórios em toda operação, os
  descritores do driver de DMA do ESP-IDF (`esp_aes_dma_core.c`). No clássico
  o driver não usa DMA e não aloca. O Ascon não aloca em nenhuma das duas.
- **Pisos do AES-GCM na Heltec variam** de 0 a 8 ciclos entre execuções
  (0,04 %), variação que não ocorre no caminho sem DMA do clássico, onde foram
  2 ciclos (0 B decifra) e 1 (32 B decifra). O Ascon teve spread 0 em tudo.
- **AES-GCM na Heltec pune tamanhos não múltiplos de 16**: 23 B custa mais que
  32 B. O driver de DMA trata o bloco parcial à parte, copiando-o para um
  buffer estático de 16 B com um par de descritores a mais
  (`esp_aes_dma_core.c:1156-1174`, ramo sem `SOC_CACHE_INTERNAL_MEM_VIA_L1CACHE`).
  É por isso que a razão é maior justamente na mensagem típica.
- **A decifra do Ascon custa mais que a cifra** por bloco (1.390 contra 1.097
  no clássico): a comparação da tag percorre o texto claro para zerá-lo em
  caso de falha (`ascon-aead-common.c:26-46`), e a macro de decifra faz uma
  escrita a mais no estado por palavra (`ascon-util-snp.h:136`). Explica parte
  da diferença; a divisão exata não foi medida.
- **Bloco parcial não é de graça**: a rotina do resto do bloco trabalha byte
  a byte, de 46 a 72 ciclos por byte. 23 B custa 6 % mais que 16 B, e 10 % menos
  que 32 B. Sem permutação extra, como o código prevê.
- **Ruído na Heltec com interrupções desligadas**: desvio de ~25 ciclos dentro
  da execução, contra 0,3 no clássico. O piso não muda. Causa provável, não
  conferida no manual: a cache é compartilhada entre os dois núcleos no S3.

O AES-CTR aparece só como instrumento de medição: cifra sem autenticar e não
atenderia ao requisito da camada. No S3 ele revela onde o custo do AES por
DMA está: 8.218 ciclos fixos por chamada e 49 por bloco. O GCM chama esse
caminho duas vezes por mensagem (dados e tag), e é isso que o torna 3,5× mais
lento que o Ascon em 23 B.

## Créditos

`ascon128a_aead_*` e `ascon_hash` da biblioteca ascon-suite (Rhys Weatherley /
Southern Storm Software, licença MIT); `mbedtls_gcm_*` e `mbedtls_aes_*` do
mbedTLS (parte do core do ESP32). Vetores de teste: KAT oficial do Ascon-128a
(`kat-validation/ASCON-128a.txt`) e Test Case 2 do GCM (McGrew e Viega). O
harness é de nossa autoria.
