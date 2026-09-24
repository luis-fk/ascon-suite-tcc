# Reprodutibilidade do tempo do Ascon-128a entre execucoes (ESP32)

Sketch complementar ao `Ascon128a_Benchmark` (Seção 3.4.3). Enquanto aquele mede
a variação **dentro** de uma execução (2000 medidas por tamanho), este repete o
benchmark **N = 100 vezes** e observa a variação **entre** execuções
independentes — outro ângulo sobre a mesma medição.

## O que ele mede

- **Entre execuções (foco):** para cada tamanho (16/32/64 B), o "piso" de cada
  execução (o mínimo de ciclos, livre de interrupção). Reporta o menor piso, o
  maior piso, o **spread** entre eles e quantas das 100 execuções atingiram o
  piso mínimo. Spread ≈ 0 ⇒ a medição é reprodutível até o ciclo.
- **Dentro de cada execução:** o desvio médio das 2000 medidas (a mesma métrica
  do single-run), reportado **em separado** — são duas fontes de variância
  distintas e não devem ser misturadas.

## Interpretação

Num ESP32 a clock fixo (240 MHz), com interrupções desabilitadas durante a
cifragem, o piso é essencialmente determinístico. O resultado esperado é
**spread 0** entre as 100 execuções. Isso **confirma** a reprodutibilidade dos
números da Seção 5.2.3 (não é uma tentativa de encontrar variabilidade) —
permite afirmar, com respaldo, que o piso reportado se repete execução após
execução.

## Como rodar

1. Placa ESP32 selecionada, biblioteca `ascon-suite` instalada.
2. Compilar e gravar `Ascon128a_Benchmark_Loop.ino`.
3. Monitor Serial em **115200**. Cada `.` é uma execução; a rodada completa leva
   ~20 s (100 × 3 tamanhos × 2000 medidas).

## Parametros

- `RUNS` (100) — execuções independentes por tamanho.
- `ITERATIONS_PER_RUN` (2000) — medidas dentro de cada execução (igual ao
  single-run, para comparabilidade direta com a Seção 5.2.3).

## Créditos

Usa `ascon128a_aead_encrypt` da biblioteca ascon-suite (Rhys Weatherley /
Southern Storm Software, licença MIT). O harness de medição é de nossa autoria.
