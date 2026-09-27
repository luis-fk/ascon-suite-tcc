# Custo de Flash do Ascon-128a

Sketch mínimo para medir quanto a biblioteca `ascon-suite` acrescenta ao
firmware. Substitui a medição antiga de 7.048 bytes (sketch `Ascon128a_Benchmark`,
removido em 27/09/2026), que não registrava a versão do core.

## Como medir

Na mesma placa, grave o sketch **duas vezes**, mudando só a linha do topo:

| Gravação | Linha | O que o firmware faz |
|---|---|---|
| 1 | `#define USE_ASCON 1` | cifra e decifra 16 bytes com a biblioteca |
| 2 | `#define USE_ASCON 0` | mesmos buffers e impressões, sem chamar a biblioteca; o ligador descarta o código dela |

Em cada gravação, anote duas coisas:

1. A linha da IDE ao fim da compilação: `Sketch uses X bytes (Y%) of program
   storage space. Maximum is Z bytes.`
2. A linha `Sketch (getSketchSize)` impressa na serial, junto com a versão do
   ESP-IDF e do core, que o sketch imprime.

**Custo do Ascon-128a = X(com) − X(sem)**, e a porcentagem é sobre o `Maximum`,
que é a partição de aplicação (1.310.720 bytes no esquema padrão do ESP32
clássico).

Repetir nas duas placas: o código de máquina do LX6 e do LX7 não tem o mesmo
tamanho.

## Resultado

Medido em 27/09/2026, core arduino-esp32 3.3.11, ESP-IDF 5.5.5. Saídas
completas em `flash-results-esp32.txt` e `flash-results-heltec.txt`.

| Placa | `Sketch uses`, com | sem | Custo do Ascon-128a | Partição (`Maximum`) | % |
|---|---|---|---|---|---|
| ESP32 clássico (ESP32-D0WDQ6) | 277.744 | 270.944 | **6.800 B** | 1.310.720 | 0,52 % |
| Heltec (ESP32-S3) | 282.257 | 275.445 | **6.812 B** | 3.342.336 | 0,20 % |

Pelo `getSketchSize()` impresso na serial, a diferença é 6.800 B nas duas
placas (277.888 − 271.088 e 282.400 − 275.600); os 12 B a mais na linha da IDE
do S3 são alinhamento da imagem. A medição antiga, 7.048 B com o core 2.0.17,
fica substituída.

Sobre a linha `Sketch + espaco livre` da serial: `getFreeSketchSpace()` devolve
o tamanho da partição de atualização OTA, não o que resta na partição atual,
então a soma não é o `Maximum` da IDE. O denominador certo é o `Maximum`.
