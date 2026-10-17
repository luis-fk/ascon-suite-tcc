# Energia por operação — Ascon-128a × AES-128-GCM (ESP32)

Medição da Seção 3.4.4. Resistor *shunt* no GND da placa, osciloscópio lendo a
tensão nele, GPIO 4 como trigger. Mede só a operação criptográfica, o rádio é da
infra. Uma cifragem dura 27 µs e some no ruído, por isso o sketch repete cada
operação 20.000 vezes (meio segundo ou mais) com o GPIO 4 alto, e a média da
tensão durante a rajada menos a média em repouso dá a corrente que a operação
acrescenta.

## O sketch

Ciclo infinito: repouso 10 s → GPIO 4 alto → 20.000 operações → GPIO 4 baixo →
pausa 200 ms → **k pulsos de 100 ms** (k = caso). Mesma chave, nonce e payload
(23 B) da suíte. Autoteste no `setup()`; se falhar, o GPIO 4 pisca a 10 Hz.

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
   **Measure** → **Ch1** → **Positive Pulse Width** → aperta (opcional).
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

O **Mean** sem "Cursor" é da tela inteira e mistura rajada e repouso, não use.

## Conta

```
ΔI = (V_raj − V_rep) / R          E_op = V_placa × ΔI × T / 20.000
```

## Resultados

**ESP32 DevKit V1 (clássico), 15/10/2026.** Leituras em
[`leituras-esp32.csv`](leituras-esp32.csv), telas em
[`capturas-esp32/`](capturas-esp32/). R = 1 Ω (1 %). Provisório em um
ponto, V_placa estimado em 3,25 V (não medido). Uma captura por caso.

| Caso | T (s) | V_raj (mV) | V_rep (mV) | ΔI (mA) | ΔP (mW) | E_op (µJ) |
|---|---|---|---|---|---|---|
| 1 controle | 0,55 | 61,6 | 48,4 | 13,2 | 43 | 1,2 |
| 2 Ascon cifra | 0,52 | 74,1 | 48,1 | 26,0 | 85 | 2,2 |
| 3 Ascon decifra | 0,57 | 74,6 | 48,0 | 26,6 | 86 | 2,5 |
| 4 GCM cifra | 1,02 | 71,4 | 52,1 | 19,3 | 63 | 3,2 |
| 5 GCM decifra | 1,05 | 71,5 | 48,4 | 23,1 | 75 | 3,9 |

Leitura: o Ascon puxa **mais potência** que o AES-GCM (a CPU calcula o tempo
todo, no GCM ela espera o acelerador), mas termina em metade do tempo, e por
operação gasta **menos energia**, 2,2 contra 3,2 µJ na cifra (1,5×) e 2,5
contra 3,9 µJ na decifra (1,6×). O controle mostra que só manter a CPU acordada
custa 13 mA; o algoritmo acrescenta outros 13. Em 23 B, a cifra Ascon custa
~0,1 µJ por byte. O *tag* de 16 B no ar a SF7 (~26 ms a 120 mA) custa ~10 mJ,
quatro mil vezes a cifragem.

Incerteza: o repouso variou de 48,0 a 52,1 mV entre janelas de 0,5 s (o
baseline deduzido da média da tela inteira fica em 48 a 50), logo ΔI tem
±2 mA, uns 10 %, bem acima do 1 % do resistor. O caso 4 com o repouso
deduzido (49,7 mV) daria 21,7 mA e 3,6 µJ. Resolução a 50 mV/div com ponta 10X é 2 mV por nível, a média sobre
250 pontos resolve abaixo disso.

**Pendente:** Heltec ESP32-S3; medir V_placa; repetir o caso 2.

## Ressalvas

- Resultado por operação de 23 B, nesta configuração. Não inclui o rádio.
- A corrente no *shunt* é da placa inteira; só a diferença entra na conta.
