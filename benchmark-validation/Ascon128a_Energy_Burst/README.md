# Energia por operação — Ascon-128a × AES-128-GCM (ESP32)

Medição da Seção 3.3.4, com os resultados na Seção 5.3.5. Resistor *shunt* no
GND da placa, osciloscópio lendo a tensão nele, GPIO 4 como trigger. Mede só a
operação criptográfica, sem o rádio. Uma cifragem dura 27 µs e some no ruído, por isso o sketch repete cada
operação 20.000 vezes (meio segundo ou mais) com o GPIO 4 alto, e a média da
tensão durante a rajada menos a média em repouso dá a corrente que a operação
acrescenta.

## O sketch

Ciclo infinito: repouso 10 s → GPIO 4 alto → 20.000 operações → GPIO 4 baixo →
pausa 200 ms → **k pulsos de 100 ms** (k = caso). Mesma chave, nonce e payload
(23 B) da suíte. Autoteste no `setup()`; se falhar, o GPIO 4 pisca a 10 Hz.
Compilar com o core arduino-esp32 3.3.x, o mesmo dos benchmarks. No 4.0.0
(mbedTLS 4) o `mbedtls/gcm.h` deixou de ser público e o sketch não compila.

| k | Caso | Rajada esperada (clássico / S3) |
|---|---|---|
| 1 | controle, espera ocupada de 27 µs por iteração | 0,54 s |
| 2 | Ascon-128a cifra | 0,54 / 0,50 s |
| 3 | Ascon-128a decifra | 0,58 / 0,52 s |
| 4 | AES-128-GCM cifra | 0,87 / 1,74 s |
| 5 | AES-128-GCM decifra | 0,91 / 1,77 s |

## Bancada

1. Gravar o sketch pelo USB, conferir o autoteste na serial. **Desconectar o
   USB** (com ele ligado, o regulador alimenta o 3V3 por fora do *shunt* e o
   GND do cabo curto-circuita o resistor).
2. Montar como na figura `setup_consumo_energia` do Cap3. Fonte 3,3 V → 3V3.
   GND da placa → terminal A do *shunt* → terminal B → GND da fonte.
3. Ponta do CH2 no terminal A, garra no terminal B. Ponta do CH1 **só a ponta**
   no D4, garra solta. Nenhuma garra no GND da placa.
4. **R** = 1 Ω, resistor de precisão (1 %). Entra direto na conta.
5. **V_placa**, uma vez: multímetro entre os pinos 3V3 e GND **da placa**
   durante uma rajada. Ou use 3,3 V menos `V_raj`.

Na Heltec V3, vista de cima com o USB para baixo, os três pinos ficam na
fileira esquerda (J3), contando a partir da antena: GND = 1º, 3V3 = 2º e 3º,
GPIO 4 = 15º. Antes de ligar a fonte: continuidade 3V3–GND sem apito, 3,3 V
entre os dois pinos só com o USB, fonte com limite de corrente baixo, positivo
ligado por último.

## Osciloscópio Tektronix TBS1072B

Pontas do laboratório: TPP0051, fixas em 10X, sem chave. Botão lateral = os
cinco à direita da tela. Multipurpose = botão giratório grande, gira e aperta.

1. **Default Setup**.
2. **1** → Probe → Voltage → Attenuation → **10X**. **2** → idem → **10X**.
3. **2** → Coupling **DC** → BW Limit **On**. Scale do CH2 → **50 mV** (ou
   20 mV). Position do CH2 → faixa no meio da tela.
4. **1** → Coupling **DC**. Scale do CH1 → **2 V**. Position do CH1 → linha
   perto da base.
5. **Trigger Menu** → Edge, Source **Ch1**, Slope **Rising**, Mode **Normal**,
   Coupling DC. Botão **Level** → **1,0 a 1,5 V** (ajuste depois do passo 2,
   mudar a atenuação multiplica o nível por dez).
6. **Acquire** → **Sample**.
7. Scale horizontal → **500 ms**. Position horizontal → marcador **T** a uma
   divisão da borda esquerda (M Pos ≈ 2 s). Apertar o botão centraliza.
8. **Measure** → **Ch2** → Multipurpose até **Cursor Mean** → aperta.
   **Measure** → **Ch2** → **Mean** → aperta (tela inteira, conferência).
   **Measure** → **Ch1** → **Positive Pulse Width** → aperta (dá o `T`).
9. **Cursor** → Type **Time**. Multipurpose move o cursor; os botões laterais
   Cursor 1 / Cursor 2 escolhem qual.
10. **Save/Recall** → Action → **Save Setup** → Save (pendrive na frente), para
    recuperar com Recall Setup na próxima vez.

## Leitura, por caso

1. **Single**. Não aperte Force Trig. Espere até 12 s, a tela congela em
   **Acq. Complete**.
2. Conte os pulsos depois do retângulo → caso.
3. Cursores logo depois da subida e logo antes da descida do retângulo →
   **Cursor Mean** = `V_raj`. Anote também o **Δt** dos cursores nas bordas.
4. Cursores num trecho com o CH1 em zero (antes do retângulo ou depois dos
   pulsos) → **Cursor Mean** = `V_rep`.
5. Foto da tela, ou Save/Recall → Action → Save Image → Save.
6. **Single** de novo para o próximo caso. Repita o caso 2 uma vez para ver se
   `V_raj` e `V_rep` se repetem.

O **Mean** sem "Cursor" é da tela inteira e mistura rajada e repouso. Não
serve de `V_raj`, mas confere o repouso da mesma captura:
`V_rep = (Mean × 5 s − V_raj × T) / (5 s − T)`.

Se o **Cursor Mean** não mudar ao mover os cursores com a tela congelada
(aconteceu em 19/11, não em 15/10), ele só está sendo calculado na captura.
Nesse caso posicione os cursores **antes** do Single e não mexa depois:
0,02 a 0,44 s para a rajada, 3,2 a 4,2 s para o repouso, uma captura para cada
leitura.

## Conta

```
ΔI = (V_raj − V_rep) / R          E_op = V_placa × ΔI × T / 20.000
```

## Resultados

Mesmo tratamento nas duas placas, o usado na monografia: um repouso por placa,
a média das cinco leituras de `V_rep`. R = 1 Ω (1 %). As leituras de cada
captura estão nos CSV e as telas nas pastas de capturas.

**ESP32 DevKit V1 (clássico), 15/10/2026.**
[`leituras-esp32.csv`](leituras-esp32.csv),
[`capturas-esp32/`](capturas-esp32/). V_placa adotado em 3,25 V, não medido.
Repouso 49,0 mV (leituras de 48,0 a 52,1 mV). T lido pelos cursores, ±0,03 s.

| Caso | T (s) | V_raj (mV) | ΔI (mA) | ΔP (mW) | E_op (µJ) |
|---|---|---|---|---|---|
| 1 controle | 0,55 | 61,6 | 12,6 | 41 | 1,1 |
| 2 Ascon cifra | 0,52 | 74,1 | 25,1 | 82 | 2,1 |
| 3 Ascon decifra | 0,57 | 74,6 | 25,6 | 83 | 2,4 |
| 4 GCM cifra | 1,02 | 71,4 | 22,4 | 73 | 3,7 |
| 5 GCM decifra | 1,05 | 71,5 | 22,5 | 73 | 3,8 |

**Heltec WiFi LoRa 32 V3 (ESP32-S3), 19/11/2026.**
[`leituras-heltec.csv`](leituras-heltec.csv),
[`capturas-heltec/`](capturas-heltec/). V_placa = 3,2 V, medido no multímetro.
Repouso 43,1 mV (leituras de 42,0 a 46,2 mV). T medido pelo Pos Width. O caso 4
é a média de duas capturas (69,8 e 72,1 mV). Core arduino-esp32 3.3.11.

| Caso | T (s) | V_raj (mV) | ΔI (mA) | ΔP (mW) | E_op (µJ) |
|---|---|---|---|---|---|
| 1 controle | 0,556 | 62,9 | 19,8 | 63 | 1,8 |
| 2 Ascon cifra | 0,499 | 71,2 | 28,1 | 90 | 2,2 |
| 3 Ascon decifra | 0,520 | 71,0 | 27,9 | 89 | 2,3 |
| 4 GCM cifra | 1,756 | 70,9 | 27,9 | 89 | 7,8 |
| 5 GCM decifra | 1,786 | 69,0 | 25,9 | 83 | 7,4 |

Leitura: a potência das duas cifras é parecida, e a diferença está no tempo. Na
Heltec o AES-GCM leva 88 µs por operação contra 25 µs do Ascon, pelo custo fixo
do acelerador com DMA, e gasta **3,5× a energia** na cifra e **3,2×** na
decifra. Na clássica a razão é 1,8× e 1,6×. O Ascon gasta entre 2,1 e 2,4 µJ
nas duas placas. O controle mostra o custo de só manter a CPU ocupada, 12,6 mA
na clássica e 19,8 mA na Heltec.

Incerteza: o repouso variou cerca de 1,8 mV (desvio padrão) entre as leituras,
nas duas placas, logo ΔI tem ±2 mA, de 7 % a 9 % nos casos com algoritmo. Na
clássica as rajadas do GCM duraram 1,02 e 1,05 s contra 0,87 e 0,91 s esperados
pelos pisos de ciclos, e a causa não foi investigada. Na Heltec as quatro
rajadas ficaram a menos de 1 % do esperado.

## Ressalvas

- Resultado por operação de 23 B, nesta configuração. Não inclui o rádio.
- A corrente no *shunt* é da placa inteira; só a diferença entra na conta.
