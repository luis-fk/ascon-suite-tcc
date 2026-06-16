/*
 * aead_demo.c
 *
 * Exemplo de uso da biblioteca ascon-suite para criptografia autenticada (AEAD)
 * com o algoritmo ASCON-128.
 *
 * Este código simula um cenário de comunicação segura ponta a ponta, onde um
 * "sensor" criptografa uma leitura e um "gateway" a descriptografa e valida.
 *
 * Como compilar (após instalar a biblioteca ascon-suite):
 * gcc -o aead_demo aead_demo.c -lascon
 *
 * Como executar:
 * ./aead_demo
 *
 * Este exemplo é colocado em domínio público.
 */

#include <stdio.h>
#include <string.h>
#include <ascon/aead.h>
#include <ascon/utility.h> // Para a função ascon_clean()

/**
 * @brief Função auxiliar para imprimir um array de bytes em formato hexadecimal.
 *
 * @param label Rótulo a ser impresso antes dos dados.
 * @param data Ponteiro para os dados.
 * @param len Comprimento dos dados.
 */
void print_hex(const char* label, const unsigned char* data, size_t len)
{
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void)
{
    printf("Demonstração de Criptografia AEAD com ASCON-128\n");
    printf("=================================================\n\n");

    /*
     * 1. DEFINIÇÃO DOS PARÂMETROS CRIPTOGRÁFICOS
     */

    // Chave secreta (k) de 16 bytes (128 bits) para ASCON-128.
    // Esta chave deve ser mantida em segredo e compartilhada apenas entre
    // o sensor e o gateway.
    // NUNCA use uma chave fixa ou previsível em uma aplicação real.
    // Ela deve ser gerada por um gerador de números aleatórios seguro.
    const unsigned char key[ASCON128_KEY_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Nonce público (npub) de 16 bytes (128 bits).
    // O nonce não precisa ser secreto, mas NUNCA DEVE SER REUTILIZADO com a
    // mesma chave para criptografar mensagens diferentes. A reutilização de
    // um par (chave, nonce) quebra a segurança do AEAD.
    // Uma estratégia comum é usar um contador que é incrementado a cada mensagem.
    const unsigned char nonce[ASCON128_NONCE_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    /*
     * 2. PAYLOAD E DADOS ASSOCIADOS (AD)
     */

    // Payload (plaintext) - a mensagem que queremos proteger (confidencialidade e integridade).
    // Neste exemplo, é uma leitura simulada de um sensor.
    const char* sensor_reading_str = "temperature: 23.5 C";
    const unsigned char* plaintext = (const unsigned char*)sensor_reading_str;
    const size_t plaintext_len = strlen(sensor_reading_str);

    // Dados Associados (Associated Data - AD) - metadados que queremos proteger
    // (apenas integridade, não confidencialidade). Eles não são criptografados,
    // mas são incluídos no cálculo da tag de autenticação.
    // Ex: ID do sensor, timestamp, cabeçalhos de protocolo, etc.
    // Se não houver dados associados, pode-se passar um ponteiro NULL ou um tamanho 0.
    const unsigned char associated_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    const size_t ad_len = sizeof(associated_data);

    printf("--- Lado do Sensor (Criptografia) ---\n");
    print_hex("Chave Secreta (k)", key, ASCON128_KEY_SIZE);
    print_hex("Nonce Público (npub)", nonce, ASCON128_NONCE_SIZE);
    printf("Payload (PT): %s\n", (const char *)plaintext);
    print_hex("Dados Associados (AD)", associated_data, ad_len);
    printf("\n");

    /*
     * 3. CRIPTOGRAFIA (LADO DO SENSOR)
     */

    // O buffer de saída (ciphertext) precisa ter espaço para o payload criptografado
    // (que tem o mesmo tamanho do original) mais a tag de autenticação.
    // Para ASCON-128, a tag tem sempre 16 bytes (ASCON128_TAG_SIZE).
    const size_t ciphertext_buffer_size = plaintext_len + ASCON128_TAG_SIZE;
    unsigned char ciphertext[ciphertext_buffer_size];
    size_t ciphertext_actual_len = 0;

    printf("Criptografando o payload...\n");
    ascon128_aead_encrypt(
        ciphertext,             // Ponteiro para o buffer de saída (ciphertext + tag).
        &ciphertext_actual_len, // Ponteiro para a variável que receberá o tamanho final.
        plaintext,              // Payload a ser criptografado.
        plaintext_len,          // Tamanho do payload.
        associated_data,        // Dados associados (autenticados, mas não criptografados).
        ad_len,                 // Tamanho dos dados associados.
        nonce,                  // Nonce público.
        key                     // Chave secreta.
    );

    print_hex("Ciphertext + Tag (CT)", ciphertext, ciphertext_actual_len);
    printf("Tamanho total enviado: %zu bytes\n", ciphertext_actual_len);
    printf("\n");

    /*
     * 4. DESCRIPTOGRAFIA (LADO DO GATEWAY)
     */
    printf("--- Lado do Gateway (Descriptografia) ---\n");

    // O buffer de saída (decrypted_plaintext) deve ter espaço suficiente
    // para o payload original. O tamanho pode ser derivado do tamanho do
    // ciphertext recebido: plaintext_len = ciphertext_len - ASCON128_TAG_SIZE.
    const size_t decrypted_buffer_size = ciphertext_actual_len > ASCON128_TAG_SIZE ? ciphertext_actual_len - ASCON128_TAG_SIZE : 0;
    unsigned char decrypted_plaintext[decrypted_buffer_size];
    size_t decrypted_plaintext_len = 0;

    printf("Descriptografando e validando a tag...\n");
    int result = ascon128_aead_decrypt(
        decrypted_plaintext,        // Ponteiro para o buffer de saída do payload descriptografado.
        &decrypted_plaintext_len,   // Ponteiro para a variável que receberá o tamanho final.
        ciphertext,                 // Ciphertext + tag a ser descriptografado.
        ciphertext_actual_len,      // Tamanho do ciphertext + tag.
        associated_data,            // Os MESMOS dados associados usados na criptografia.
        ad_len,                     // Tamanho dos dados associados.
        nonce,                      // O MESMO nonce público.
        key                         // A MESMA chave secreta.
    );

    /*
     * 5. VALIDAÇÃO DO RESULTADO
     */
    printf("\n--- Validação ---\n");
    if (result == 0) {
        // A função retornou 0, o que significa que a tag de autenticação é VÁLIDA.
        // A descriptografia foi bem-sucedida e os dados são autênticos.
        printf("SUCESSO! A descriptografia foi bem-sucedida e a tag é válida.\n");
        printf("Payload recuperado: %.*s\n", (int)decrypted_plaintext_len, decrypted_plaintext);

        // Verificação final para garantir que o payload original e o recuperado são idênticos.
        if (plaintext_len == decrypted_plaintext_len && memcmp(plaintext, decrypted_plaintext, plaintext_len) == 0) {
            printf("Verificação OK: Payload original e recuperado são idênticos.\n");
        } else {
            printf("ERRO NA VERIFICAÇÃO: Payload original e recuperado são diferentes!\n");
        }
    } else {
        // A função retornou -1, o que significa que a tag de autenticação é INVÁLIDA.
        // Os dados podem ter sido corrompidos ou adulterados durante a transmissão.
        // O conteúdo do buffer `decrypted_plaintext` é indefinido e NÃO DEVE SER USADO.
        printf("FALHA! A descriptografia falhou (código de retorno: %d). A tag é inválida.\n", result);
        printf("Os dados podem ter sido adulterados! Descarte o pacote.\n");
    }

    // Limpa a chave da memória por segurança, para evitar que ela permaneça
    // em um dump de memória, por exemplo.
    ascon_clean((void*)key, sizeof(key));

    return result;
}
