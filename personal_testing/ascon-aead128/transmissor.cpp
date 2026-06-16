/*
 * NÓ TRANSMISSOR (SENSOR)
 * Exemplo de uso da biblioteca ascon-suite para criptografia AEAD (ASCON-128)
 * com transmissão sem fio via ESP-NOW.
 */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <ASCON.h>
#include <ascon/aead.h>
#include <ascon/utility.h>
#include <Preferences.h>

Preferences preferences;

// MAC Address do Nó Receptor (Gateway)
// Para o tutorial, o endereço de Broadcast (FF:FF:FF:FF:FF:FF) facilita os testes, 
// pois envia para todos os ESP32 na área. Em produção, use o MAC exato do receptor.
uint8_t receiverMACAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
esp_now_peer_info_t peerInfo;

// 1. DEFINIÇÃO DOS PARÂMETROS CRIPTOGRÁFICOS (Compartilhados)
// Chave secreta (k) de 16 bytes. NUNCA use chave fixa em produção!
unsigned char key[ASCON128_KEY_SIZE];

// Contador de mensagens para gerar nonces únicos. Será persistido na NVS.
uint32_t message_counter;

// Nonce público (npub) de 16 bytes. NUNCA REUTILIZE o mesmo nonce com a mesma chave.
unsigned char nonce[ASCON128_NONCE_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Dados Associados (AD) - Metadados protegidos contra alteração, mas não ocultos.
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

void setup() {
    Serial.begin(115200);
    delay(2000); // Tempo para abrir o Monitor Serial
    
    Serial.println("\n--- Lado do Sensor (Transmissor) ---");

    // --- CARREGAMENTO DA CHAVE (NVS) ---
    preferences.begin("ascon_sec", true); // true = Somente leitura
    size_t bytes_lidos = preferences.getBytes("master_key", key, ASCON128_KEY_SIZE);
    preferences.end();

    if (bytes_lidos != ASCON128_KEY_SIZE) {
        Serial.println("ERRO FATAL: Chave não encontrada na NVS. Rode o script gravador!");
        while(true); // Trava o sistema por segurança
    }
    Serial.println("Chave carregada da memória com sucesso.");

    // --- INICIALIZAÇÃO DO CONTADOR DE MENSAGENS (PARA O NONCE) ---
    preferences.begin("msg_cnt", false); // Abre no modo Leitura/Escrita
    
    // Lê o último contador salvo. Se não existir, começa em 0.
    uint32_t last_counter = preferences.getUInt("msg_cnt", 0);
    
    // Aplica uma margem de segurança para evitar reutilização de nonce em caso de reset.
    // A margem de segurança (100) deve ser igual ou maior que o intervalo de salvamento (a cada 100 mensagens).
    // Isso garante que, em caso de reset, o novo contador comece após o último nonce possivelmente usado.
    message_counter = last_counter + 100; 
    Serial.printf("Contador recuperado: %u. Iniciando a partir de: %u\n", last_counter, message_counter);
    preferences.end();

    // --- INICIALIZAÇÃO DO ESP-NOW ---
    // Coloca o ESP32 em modo Station (necessário para o ESP-NOW)
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != ESP_OK) {
        Serial.println("Erro ao inicializar o ESP-NOW");
        return;
    }

    // Configura e registra o Nó Receptor (Gateway)
    memcpy(peerInfo.peer_addr, receiverMACAddress, 6);
    peerInfo.channel = 0;  // Canal Wi-Fi padrão
    // IMPORTANTE: Desligamos a criptografia nativa do ESP-NOW (CCMP),
    // pois a nossa aplicação já está utilizando a criptografia leve do Ascon!
    peerInfo.encrypt = false; 

    if (esp_now_add_peer(&peerInfo) != ESP_OK) {
        Serial.println("Falha ao registrar o receptor");
        return;
    }
    Serial.println("Rede ESP-NOW configurada com sucesso.\n");
}

void loop() {
    // 1. PAYLOAD (A mensagem a ser protegida)
    const char* sensor_reading_str = "temperatura: 23.5 C";
    const unsigned char* plaintext = (const unsigned char*)sensor_reading_str;
    const size_t plaintext_len = strlen(sensor_reading_str);

    // IMPORTANTE: Atualizar o nonce ANTES de cada criptografia para garantir que ele seja único.
    // Incrementamos nosso contador e o copiamos para a parte final do array do nonce.
    message_counter++;
    memcpy(nonce + 12, &message_counter, sizeof(message_counter));

    Serial.printf("\nPayload original (PT): %s\n", sensor_reading_str);

    // 2. CRIPTOGRAFIA E MONTAGEM DO PACOTE
    // O pacote final terá o formato: [ 16 bytes de Nonce | Ciphertext + Tag ]
    
    // Buffer para o pacote completo. O tamanho máximo do ESP-NOW é 250 bytes.
    unsigned char full_packet[250]; 
    size_t ciphertext_actual_len = 0;

    // Passo 2.1: Copia o nonce para o início do pacote
    memcpy(full_packet, nonce, ASCON128_NONCE_SIZE);

    print_hex("Nonce usado", nonce, ASCON128_NONCE_SIZE);
    Serial.println("Criptografando o payload com Ascon-128...");
    
    // Passo 2.2: Criptografa o payload, salvando o resultado (CT + Tag) LOGO APÓS o nonce
    ascon128_aead_encrypt(
        full_packet + ASCON128_NONCE_SIZE, // Buffer de saída (após o nonce)
        &ciphertext_actual_len,            // Tamanho final gerado (apenas CT + Tag)
        plaintext,                         // Payload original
        plaintext_len,                     // Tamanho do payload
        associated_data,                   // Dados associados
        ad_len,                            // Tamanho dos dados associados
        nonce,                             // Nonce público
        key                                // Chave secreta
    );

    // O tamanho total a ser enviado é o nonce (16) + o ciphertext com a tag
    const size_t total_len_to_send = ASCON128_NONCE_SIZE + ciphertext_actual_len;

    // Exibe o pacote final pronto para envio
    print_hex("Pacote Completo (Nonce + CT + Tag)", full_packet, total_len_to_send);
    
    // 3. TRANSMISSÃO VIA ESP-NOW
    Serial.println("Transmitindo dados pelo ar...");
    esp_err_t result = esp_now_send(receiverMACAddress, full_packet, total_len_to_send);
    
    if (result == ESP_OK) {
        Serial.println("Comando de envio acionado com sucesso.");
    } else {
        Serial.println("Erro ao enviar o pacote.");
    }

    // Persiste o contador na NVS periodicamente para reduzir o desgaste da flash.
    if (message_counter % 100 == 0) {
        preferences.begin("msg_cnt", false);
        preferences.putUInt("msg_cnt", message_counter);
        preferences.end();
        Serial.printf("-> Contador de mensagens (%u) salvo na NVS.\n", message_counter);
    }

    delay(5000);
}