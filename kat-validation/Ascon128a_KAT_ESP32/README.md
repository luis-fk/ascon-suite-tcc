# Validação KAT na placa — Ascon-128a (ESP32)

Sketch Arduino que roda um subconjunto representativo dos *Known Answer Tests*
do Ascon-128a diretamente no ESP32. É a segunda parte da Seção 3.4.1: depois de
validar a biblioteca de forma exaustiva no desktop, confirmamos
na própria placa que a compilação e a arquitetura (Xtensa LX, *little-endian*) não
introduzem nenhuma divergência.

## O que ele faz

Para cada vetor, o sketch (1) cifra e compara o resultado (`ciphertext || tag`)
com o valor oficial esperado e (2) decifra esse valor e confirma que o texto
claro é recuperado com a *tag* validada. O resultado de cada vetor e um resumo
final são impressos na Serial (115200 baud).

## Vetores escolhidos

Não rodamos os 1089 vetores na placa porque o desktop já cobre a corretude
matemática; aqui basta exercitar os limites que poderiam expor um problema de
compilação/arquitetura. Os seis vetores foram extraídos do `ASCON-128a.txt`
oficial e cobrem:

| Vetor | Por que | Origem (Count) |
|-------|---------|----------------|
| PT=0 AD=0   | tudo vazio (só a *tag*)        | 1 |
| PT=0 AD=16  | sem texto, AD de um bloco      | 17 |
| PT=5 AD=0   | bloco parcial de texto         | 166 |
| PT=16 AD=0  | exatamente um bloco            | 529 |
| PT=1 AD=1   | mínimo em ambos                | 35 |
| PT=32 AD=32 | múltiplos blocos em ambos      | 1089 |

## Como rodar

1. Instalar a biblioteca `ascon-suite` no Arduino IDE (ou apontar para este
   repositório como biblioteca local).
2. Selecionar a placa ESP32 e a porta serial.
3. Compilar e gravar `Ascon128a_KAT_ESP32.ino`.
4. Abrir o Monitor Serial em **115200** e observar a saída.

Saída esperada: cada vetor seguido de `OK` e, ao final,
`>>> TODOS OS VETORES PASSARAM NA PLACA <<<`.

## Resultado

Os 6 vetores passaram na placa (6/6), confirmando que a compilação e a
arquitetura do ESP32 reproduzem exatamente os valores de referência. O log da
execução está em `kat-esp32-results.log`. O estado interno do algoritmo
(`ascon128a_state_t`) ocupou 80 bytes na placa.

## Créditos

A estrutura do teste foi adaptada do exemplo `Ascon128_Test` da biblioteca
ascon-suite (Rhys Weatherley / Southern Storm Software, licença MIT). Os vetores
vêm do arquivo de referência `ASCON-128a.txt`. A nossa parte é a seleção do
subconjunto, a adaptação para o Ascon-128a e a execução na placa.
