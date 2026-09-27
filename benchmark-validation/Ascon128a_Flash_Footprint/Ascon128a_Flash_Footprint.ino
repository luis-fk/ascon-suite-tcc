// Quanto de Flash o Ascon-128a acrescenta ao firmware.
//
// Grave DUAS vezes na mesma placa, mudando so a linha abaixo, e compare o
// "sketch" impresso na serial (e a linha "Sketch uses ... bytes" da IDE):
//
//   #define USE_ASCON 1   -> firmware que cifra e decifra com a biblioteca
//   #define USE_ASCON 0   -> mesmo firmware, sem nenhuma chamada a biblioteca;
//                            o ligador descarta o codigo dela (gc-sections)
//
// A diferenca entre os dois "sketch" e o custo de Flash do Ascon-128a. Tudo o
// mais (Serial, laco, buffers, impressao) e identico nas duas gravacoes.

#define USE_ASCON 1

#include <ASCON.h>

#if defined(__has_include)
#  if __has_include("esp_idf_version.h")
#    include "esp_idf_version.h"
#    define IDF_VERSION_REACHED 1
#  endif
#  if __has_include("esp_arduino_version.h")
#    include "esp_arduino_version.h"
#    define ARDUINO_VERSION_REACHED 1
#  endif
#endif

static uint8_t key[16]        = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
static uint8_t nonce[16]      = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
static uint8_t plaintext[16]  = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
static uint8_t ciphertext[32];
static uint8_t recovered[16];

void setup()
{
  Serial.begin(115200);
  delay(300);

  Serial.println();
  Serial.print("=== Custo de Flash do Ascon-128a: USE_ASCON = ");
  Serial.println(USE_ASCON);

#ifdef CONFIG_IDF_TARGET
  Serial.print("Alvo (CONFIG_IDF_TARGET) : "); Serial.println(CONFIG_IDF_TARGET);
#endif
#ifdef IDF_VERSION_REACHED
  Serial.printf("ESP-IDF                  : %d.%d.%d\n", ESP_IDF_VERSION_MAJOR, ESP_IDF_VERSION_MINOR, ESP_IDF_VERSION_PATCH);
#endif
#ifdef ARDUINO_VERSION_REACHED
  Serial.printf("Core arduino-esp32       : %d.%d.%d\n", ESP_ARDUINO_VERSION_MAJOR, ESP_ARDUINO_VERSION_MINOR, ESP_ARDUINO_VERSION_PATCH);
#endif
  Serial.printf("Chip                     : %s\n", ESP.getChipModel());
  Serial.printf("Sketch (getSketchSize)   : %u bytes\n", (unsigned) ESP.getSketchSize());
  // getFreeSketchSpace() e o tamanho da particao OTA, nao o que resta nesta;
  // o denominador para a porcentagem e o "Maximum" que a IDE imprime.
  Serial.printf("Sketch + espaco livre    : %u bytes (getSketchSize + getFreeSketchSpace)\n",
                (unsigned) (ESP.getSketchSize() + ESP.getFreeSketchSpace()));

  size_t ciphertextLength = 0;
  size_t recoveredLength  = 0;
  int    result           = 0;

#if USE_ASCON
  ascon128a_aead_encrypt(ciphertext, &ciphertextLength, plaintext, 16, NULL, 0, nonce, key);
  result = ascon128a_aead_decrypt(recovered, &recoveredLength, ciphertext, ciphertextLength, NULL, 0, nonce, key);
#else
  // Mesmos buffers, mesmo caminho de impressao, nenhuma chamada a biblioteca.
  memcpy(ciphertext, plaintext, 16);
  ciphertextLength = 16;
  memcpy(recovered, ciphertext, 16);
  recoveredLength = 16;
#endif

  // Imprime os resultados, e um byte da chave e do nonce, para que o compilador
  // mantenha os mesmos buffers nas duas variantes: so a biblioteca pode diferir.
  Serial.printf("Cifra: %u bytes, decifra: %u bytes, retorno %d, bytes 0x%02x 0x%02x 0x%02x\n",
                (unsigned) ciphertextLength, (unsigned) recoveredLength, result,
                recovered[0], key[0], nonce[0]);
  Serial.println(">>> anote o valor de 'Sketch' e a linha 'Sketch uses' da IDE <<<");
}

void loop()
{
  delay(1000);
}
