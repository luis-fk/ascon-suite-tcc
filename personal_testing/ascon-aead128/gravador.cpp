/*
 * SCRIPT DE PROVISIONAMENTO (O Gravador)
 * Este código serve APENAS para salvar a chave na memória NVS do ESP32.
 * Após rodar com sucesso, você gravará o código do Transmissor/Receptor por cima dele.
 */

#include <Arduino.h>
#include <Preferences.h>
#include <ASCON.h>

Preferences preferences;

// Cole aqui a chave de 16 bytes que você gerou no seu PC
const unsigned char key_to_save[16] = {
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, // <-- Substitua pelos seus bytes
    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89  // <-- Substitua pelos seus bytes
};

void setup() {
    Serial.begin(115200);
    delay(2000);
    
    Serial.println("\n--- Iniciando Provisionamento Seguro ---");

    // Abre um "namespace" (uma pastinha) chamada "ascon_sec" no modo Leitura/Escrita (false)
    preferences.begin("ascon_sec", false);

    // Salva o vetor de bytes criando um rótulo chamado "master_key"
    size_t bytes_salvos = preferences.putBytes("master_key", key, 16);

    if (bytes_salvos == 16) {
        Serial.println("SUCESSO! A chave de 128 bits foi salva permanentemente na NVS.");
        Serial.println("Você já pode carregar o código final (Transmissor/Receptor) nesta placa.");
    } else {
        Serial.println("ERRO CRÍTICO: Falha ao gravar na memória Flash.");
    }

    // Fecha o banco de dados
    preferences.end();
}

void loop() {
}