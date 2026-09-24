# O GCM é mesmo acelerado por hardware neste ESP32?

Sketch de verificação da afirmação usada na Seção 5.2.4:

> "no ESP32 clássico, apenas o bloco AES é executado no acelerador de hardware;
> a autenticação (GHASH) permanece em software"

Essa frase sustenta a interpretação de todo o comparativo Ascon × AES, então
convém **comprová-la na própria placa**, e não apenas citá-la.

## Dois caminhos independentes

**[1] Capacidade declarada (tempo de compilação).** Lê as macros do SDK que
compilou este firmware:

| Macro | O que indica |
|---|---|
| `SOC_AES_SUPPORT_GCM` | definida pelo ESP-IDF só para chips cujo acelerador AES tem GCM |
| `SOC_AES_SUPPORT_DMA` | acelerador AES com DMA |
| `CONFIG_MBEDTLS_HARDWARE_AES` | bloco AES pelo hardware |
| `CONFIG_MBEDTLS_HARDWARE_GCM` | GCM pelo hardware |
| `MBEDTLS_AES_ALT` / `MBEDTLS_GCM_ALT` | o *port* da Espressif substitui a implementação do mbedTLS. **Não** indica aceleração de GCM: o *port* usa o hardware para o bloco AES e calcula o GHASH em software |

Se `soc/soc_caps.h` não for encontrado, o sketch reporta o item como
**inconclusivo** — em vez de confundir "macro ausente" com "header ausente", o
que produziria um falso negativo.

**[2] Evidência empírica (tempo de execução).** Mede o custo **marginal por
bloco de 16 B** de quatro caminhos, na mesma placa:

- `AES-CTR` — só a cifra AES (acelerador), **sem** autenticação
- `AES-GCM` — a mesma cifra AES **+** o GHASH
- `AES-ECB` bloco a bloco — expõe o custo da camada de *port* quando pago por
  bloco, e não por chamada
- `Ascon-128a` — referência em software puro

A diferença `GCM − CTR` isola o custo do GHASH por bloco. A subtração é exata,
e não aproximada: no ESP-IDF, `esp_aes_gcm.c:538` chama literalmente
`esp_aes_crypt_ctr`, a mesma função que o caminho `AES-CTR` mede.

Usa-se o custo *marginal* (inclinação entre 16 e 64 B), não o total, para
cancelar a parcela fixa de cada API (aquisição do periférico, `setkey`,
chamada). A linearidade é conferida com o ponto intermediário de 32 B: se a
reta não descrever os dados, o sketch se recusa a concluir.

## Como interpretar

A régua é o manual do fabricante: o ESP32 TRM v5.8, seção 14.3.5, diz que o
núcleo do acelerador cifra um bloco em **11 a 15 ciclos**.

| GHASH por bloco | Leitura |
|---|---|
| mesma ordem do bloco (dezenas) | autenticação acelerada por **hardware** |
| ordens de grandeza acima | multiplicação em GF(2$^{128}$) por tabelas → **software** |

Os dois itens devem concordar. Se discordarem, o item [2] prevalece: ele mede o
que o firmware **de fato executa**, enquanto as macros dizem apenas o que foi
compilado.

## Como rodar

1. Placa ESP32 selecionada, biblioteca `ascon-suite` instalada (mbedTLS já vem no
   core do ESP32).
2. Compilar e gravar `AES_HardwareCheck.ino`.
3. Monitor Serial em **115200**. Leva alguns segundos.

Metodologia de tempo idêntica à da Seção 3.4.3: mínimo de ciclos (piso livre de
interrupção), 2.000 medidas por ponto. Não se desabilitam interrupções em volta da
chamada porque o próprio driver de AES já o faz: ele protege o periférico com um
*spinlock* e entra em seção crítica durante a operação de bloco
(`portENTER_CRITICAL`, em `port/aes/block/esp_aes.c:58`). O piso de 2.000 medidas
remove o ruído restante, e é o mesmo método aplicado ao Ascon, o que mantém a
comparação justa.

## Se a afirmação não se confirmar

O texto da Seção 5.2.4 precisa ser corrigido. É justamente para isso que o
teste existe.

Sobre a ressalva de outros chips: entre os sete alvos do ESP-IDF v5.1.4, apenas
o **ESP32-S2** declara `SOC_AES_SUPPORT_GCM`, e mesmo nele o Kconfig da
Espressif registra que *"GHASH calculation is still done in software"*. O S3 e o
C3 têm DMA no AES, não GCM.
