/*
 * NÓ RECEPTOR (GATEWAY)
 * Exemplo de uso da biblioteca ascon-suite para descriptografia AEAD (ASCON-128)
 * recebendo pacotes sem fio de forma assíncrona via ESP-NOW.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <ascon/aead.h>
#include <ascon/utility.h>
#include <Preferences.h>

Preferences preferences;

// 1. DEFINIÇÃO DOS PARÂMETROS CRIPTOGRÁFICOS (Idênticos ao Transmissor)
unsigned char key[ASCON128_KEY_SIZE];

const unsigned char associated_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
const size_t ad_len = sizeof(associated_data);

// Função auxiliar para imprimir bytes em formato hexadecimal no Monitor Serial
void print_hex(const char* label, const unsigned char* data, size_t len) {
    Serial.printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; ++i) {
        Serial.printf("%02x", data[i]);
    }
    Serial.println();
}

// 2. FUNÇÃO DE RECEBIMENTO (Callback ESP-NOW)
// Executada automaticamente toda vez que um pacote chega na antena
void OnDataRecv(const uint8_t * mac, const uint8_t *incomingData, int len) {
    Serial.println("\n--- Novo Pacote Recebido ---");
    Serial.printf("Tamanho recebido no ar: %d bytes\n", len);

    // Separa o nonce e o ciphertext do pacote recebido
    const unsigned char* received_nonce = incomingData;
    const unsigned char* ciphertext_with_tag = incomingData + ASCON128_NONCE_SIZE;
    const size_t ciphertext_len = len - ASCON128_NONCE_SIZE;

    // 3. DESCRIPTOGRAFIA
    // Usamos um buffer de tamanho fixo e seguro. O payload máximo do ESP-NOW é 250 bytes.
    unsigned char decrypted_plaintext[251]; // 250 para dados + 1 para o terminador nulo
    size_t decrypted_plaintext_len = 0;

    Serial.println("Processando pacote e validando Tag de Autenticação...");
    print_hex("Nonce recebido", received_nonce, ASCON128_NONCE_SIZE); 
    
    int result = ascon128_aead_decrypt(
        decrypted_plaintext,        // Buffer para o texto original
        &decrypted_plaintext_len,   // Tamanho final recuperado
        ciphertext_with_tag,        // Pacote criptografado (sem o nonce)
        ciphertext_len,             // Tamanho do pacote criptografado
        associated_data,            // Os MESMOS dados associados
        ad_len,                     // Tamanho dos dados associados
        received_nonce,             // O nonce que veio no pacote
        key                         // A MESMA chave secreta
    );

    // 4. VALIDAÇÃO DO RESULTADO
    Serial.println("--- Resultado da Autenticação ---");
    if (result == 0) {
        // Tag validada com sucesso!
        decrypted_plaintext[decrypted_plaintext_len] = '\0'; // Garante o fim da string para imprimir
        Serial.println("SUCESSO! Pacote integro e autêntico.");
        Serial.printf("Mensagem decifrada: %s\n", (char*)decrypted_plaintext);
    } else {
        // Tag inválida! Dados corrompidos, chave errada ou interceptação.
        Serial.printf("ALERTA DE SEGURANÇA! Falha na autenticação (Código: %d).\n", result);
        Serial.println("O pacote foi descartado de forma segura.");
    }
}

void setup() {
    Serial.begin(115200);
    delay(2000); // Tempo para abrir o Monitor Serial

    // --- CARREGAMENTO DA CHAVE (NVS) ---
    preferences.begin("ascon_sec", true); // true = Somente leitura
    size_t bytes_lidos = preferences.getBytes("master_key", key, ASCON128_KEY_SIZE);
    preferences.end();

    if (bytes_lidos != ASCON128_KEY_SIZE) {
        Serial.println("ERRO FATAL: Chave não encontrada na NVS. Rode o script gravador!");
        while(true); // Trava o sistema por segurança
    }
    Serial.println("Chave carregada da memória segura com sucesso.");

    Serial.println("\n--- Lado do Gateway (Receptor) ---");

    // --- INICIALIZAÇÃO DO ESP-NOW ---
    // Coloca o ESP32 em modo Station (necessário para o ESP-NOW)
    WiFi.mode(WIFI_STA);
    
    if (esp_now_init() != ESP_OK) {
        Serial.println("Erro ao inicializar o ESP-NOW");
        return;
    }

    // Registra a função de callback para escutar a rede
    // O cast para esp_now_recv_cb_t evita avisos de compilação na IDE do Arduino
    esp_now_register_recv_cb((esp_now_recv_cb_t)OnDataRecv);

    Serial.println("Gateway pronto e escutando a rede ESP-NOW aguardando sensores...");
}

void loop() {
    // O loop fica vazio.
    // O ESP32 gerencia o recebimento de forma assíncrona em segundo plano,
    // disparando a função OnDataRecv apenas quando necessário.
}