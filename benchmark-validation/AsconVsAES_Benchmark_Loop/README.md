# Reprodutibilidade da razão AES/Ascon entre execuções (ESP32)

Sketch complementar ao `AsconVsAES_Benchmark` (Seção 3.4.3 / 5.2.4). Aquele mede
o comparativo numa única execução; este repete o comparativo **N = 100 vezes**
por tamanho e observa a estabilidade da **razão AES/Ascon** entre execuções
independentes.

## Por que a razão é a métrica principal

A razão é o resultado central do trabalho (software leve × silício dedicado).
Mostrar que ela se repete execução após execução é mais forte do que reportar um
único número — e a razão ainda **cancela fatores comuns** às duas medições
(overhead do laço de medição, estado do cache), já que ambas passam pelo mesmo
harness na mesma run.

## O que ele reporta

Para cada tamanho (16/32/64 B):

- **Piso por algoritmo:** menor piso, maior piso, *spread*, média e quantas das
  100 execuções atingiram o piso mínimo — separadamente para Ascon e AES-GCM.
- **Razão AES/Ascon:** mínima, máxima e média entre as 100 execuções.
- **Contagem de vitórias:** em quantas execuções o piso do Ascon ficou abaixo do
  piso do AES-GCM (esperado: 100/100 em todos os tamanhos).

No fim, um veredito agregado sobre as 300 execuções (3 tamanhos × 100).

## Metodologia (idêntica à do comparativo de execução única)

Como o driver de AES por hardware adquire um *mutex* (proibido dentro de seção
crítica), **não** se desabilitam interrupções aqui. Para uma comparação justa,
usa-se o **mínimo de ciclos** (piso livre de interrupção) de **ambos** os
algoritmos — a mesma escolha da Seção 5.2.4.

Ressalva que vale repetir na escrita: no ESP32 clássico o GCM **não** é 100%
hardware (só o bloco AES; o GHASH é software). Em chips com GCM em hardware
(S2/S3/C3) o resultado do AES poderia ser melhor.

## Como rodar

1. Placa ESP32 selecionada, biblioteca `ascon-suite` instalada (mbedTLS já vem
   no core do ESP32).
2. Compilar e gravar `AsconVsAES_Benchmark_Loop.ino`.
3. Monitor Serial em **115200**. Cada `.` é uma execução; a rodada completa leva
   **~1 minuto** (100 × 3 tamanhos × 2000 medidas × 2 algoritmos).

## Parâmetros

- `RUNS` (100) — execuções independentes por tamanho.
- `ITERATIONS_PER_RUN` (2000) — medidas dentro de cada execução (igual ao
  single-run, para comparabilidade direta com a Seção 5.2.4).

## Créditos

`ascon128a_aead_*` da biblioteca ascon-suite (Rhys Weatherley / Southern Storm,
MIT) e `mbedtls_gcm_*` do mbedTLS (parte do core do ESP32). O harness de
comparação é de nossa autoria.
