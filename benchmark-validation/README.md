# Benchmarks — Ascon-128a no ESP32

Medições de memória, tempo de execução, tempo constante e comparativo com o
AES-128-GCM (Seções 3.4.3, 5.2.3 e 5.2.4 do TCC), feitas nas duas placas do
projeto: ESP32 clássico (Xtensa LX6) e Heltec WiFi LoRa 32 V3 (ESP32-S3,
Xtensa LX7), ambas a 240 MHz com o core arduino-esp32 3.3.11 (ESP-IDF 5.5.5).

| Pasta | O que mede | Saída |
|---|---|---|
| [`Ascon128a_Benchmark_Suite/`](Ascon128a_Benchmark_Suite/) | heap lido continuamente durante a operação, pilha por tarefa, piso de 2.000 medidas em 100 execuções por tamanho (0, 2, 16, 23, 32 e 64 B), tempo constante com cinco classes de entrada, Ascon-128a contra AES-128-GCM e AES-128-CTR (mbedTLS), verificação do que o acelerador de AES faz em cada chip | `bench-results-esp32.txt`, `bench-results-heltec.txt`. `parse_results.py` imprime as tabelas; `make_figures.py` gera as figuras do Cap5 |
| [`Ascon128a_Flash_Footprint/`](Ascon128a_Flash_Footprint/) | custo de Flash da biblioteca, por diferença entre dois builds do mesmo sketch | `flash-results-esp32.txt`, `flash-results-heltec.txt` |

Cada pasta tem um README com o método, os resultados das duas placas e as
ressalvas. Os números citados no Cap5 saem desses logs sem retoque.

Histórico: até 27/09/2026 as medições estavam em cinco sketches separados
(`Ascon128a_Benchmark`, `Ascon128a_Benchmark_Loop`, `AsconVsAES_Benchmark`,
`AsconVsAES_Benchmark_Loop` e `AES_HardwareCheck`), com builds diferentes e
pisos ligeiramente diferentes entre si. A suíte os substituiu e eles saíram do
repositório; o histórico do git os guarda.
