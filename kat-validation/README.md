# Validação KAT — Ascon-128a

Aqui ficam as evidências de que a implementação do Ascon-128a (v1.2) que usamos
no trabalho passa nos testes oficiais de vetores conhecidos (Known Answer
Tests). É a etapa de validação matemática em desktop descrita na Seção 3.4.1.

## Arquivos

- `ASCON-128a.txt` — os 1089 vetores oficiais (Key, Nonce, PT, AD → CT).
- `kat-results.log` — a saída da execução, com data, máquina, compilador e commit.

## Resultado

Os 1089 vetores bateram com a saída esperada, a regeneração ficou idêntica à
referência e os 14 testes do CTest passaram. Os detalhes estão no log.

## Escopo

A validação é do Ascon-128a, finalista da competição (v1.2), que é
estruturalmente equivalente ao Ascon-AEAD128 padronizado (SP 800-232). A
justificativa dessa equivalência está nas Seções 2.2.1 e 3.2.5.

## Como reproduzir

Depois de compilar a suíte (`cmake .. && make kat kat-gen` dentro de `build/`),
a partir da raiz do repositório:

```bash
./build/test/kat/kat ASCON-128a - < kat-validation/ASCON-128a.txt
./build/test/kat/kat-gen ASCON-128a - | diff - kat-validation/ASCON-128a.txt
( cd build && ctest -R ASCON-128a --output-on-failure )
```

## Créditos

Os vetores e o programa de teste que gerou esse log não são de nossa autoria:
fazem parte da biblioteca ascon-suite, de Rhys Weatherley / Southern Storm
Software (© 2021), sob licença MIT (https://github.com/rweather/ascon-suite).
A nossa parte é a validação em si e a leitura dos resultados no contexto do
trabalho.
