/*
 * Gerador de Chave Segura (Ascon-128) para PC
 * Utiliza mbedTLS para demonstrar o fluxo: Entropia do SO -> CTR_DRBG -> Chave
 */

#include <stdio.h>
#include <string.h>

// Bibliotecas do mbedTLS para Entropia e DRBG
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define ASCON128_KEY_SIZE 16 // 16 bytes = 128 bits

int main() {
    // 1. Estruturas de contexto do mbedTLS
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    unsigned char key[ASCON128_KEY_SIZE];
    
    // Uma string de personalização ajuda a isolar as instâncias do DRBG.
    // Pode ser qualquer texto identificando o seu projeto.
    const char *personalization = "Projeto_Seguranca_Ascon_TCC";

    // 2. Inicialização dos contextos
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf("Coletando entropia do sistema operacional...\n");

    // 3. Alimentando o DRBG com a Entropia (Seeding)
    // Aqui o mbedTLS puxa dados imprevisíveis do PC (ex: /dev/urandom no Linux)
    // e usa o algoritmo CTR_DRBG para criar um estado criptográfico seguro.
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)personalization,
                                    strlen(personalization));
    if (ret != 0) {
        printf("Falha crítica: Erro ao injetar entropia no DRBG (Código: -0x%04x)\n", -ret);
        return 1;
    }

    printf("DRBG inicializado com sucesso. Gerando chave de %d bytes...\n\n", ASCON128_KEY_SIZE);

    // 4. Extraindo os bits aleatórios determinísticos para a nossa chave
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, ASCON128_KEY_SIZE);
    if (ret != 0) {
        printf("Falha crítica: Erro ao gerar os números aleatórios (Código: -0x%04x)\n", -ret);
        return 1;
    }

    // 5. Imprimindo a chave formatada para uso no ESP32
    printf("================ CHAVE GERADA ================\n");
    printf("Copie e cole o bloco abaixo no código dos seus ESP32:\n\n");
    
    printf("const unsigned char key[ASCON128_KEY_SIZE] = {\n    ");
    for (int i = 0; i < ASCON128_KEY_SIZE; i++) {
        printf("0x%02x", key[i]);
        if (i < ASCON128_KEY_SIZE - 1) {
            printf(", ");
        }
    }
    printf("\n};\n");
    printf("==============================================\n\n");

    // 6. Limpeza de memória (Boas práticas)
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}