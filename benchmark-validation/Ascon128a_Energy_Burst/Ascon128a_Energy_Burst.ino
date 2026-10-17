// Rajadas para medir a energia da cifragem com shunt e osciloscopio (Secao 3.4.4).
//
// Montagem: figura "setup_consumo_energia" do Cap3. Fonte de 3,3 V no pino 3V3,
// GND da placa -> resistor shunt -> GND da fonte. CH2 do osciloscopio no shunt,
// CH1 no GPIO 4 (trigger).
//
// O que a placa faz, em ciclo, para cada caso:
//   repouso (IDLE_MS) -> GPIO 4 alto -> ITERATIONS operacoes -> GPIO 4 baixo
//   -> pausa curta -> k pulsos de 100 ms no GPIO 4 (k identifica o caso)
//
// No osciloscopio, use holdoff de trigger de ~4 s para os pulsos nao
// redispararem a captura (ver README).
//
// Casos (k pulsos):
//   1  espera ocupada de CONTROL_US por iteracao (controle: CPU acordada, sem cifra)
//   2  Ascon-128a cifra
//   3  Ascon-128a decifra
//   4  AES-128-GCM cifra   (mbedTLS, bloco AES no acelerador)
//   5  AES-128-GCM decifra
// Mesma chave, nonce e payload da suite de benchmark.
//
// Energia por operacao = V_placa * (I_rajada - I_repouso) * T_rajada / ITERATIONS
// T_rajada e a largura do retangulo no CH1; tambem sai na serial quando o USB
// estiver ligado. Durante a medicao o USB fica DESLIGADO: com ele ligado, o
// regulador da placa alimenta o 3V3 por fora do shunt e parte da corrente some.
//
// Se o autoteste do setup() falhar, o GPIO 4 pisca rapido para sempre.

#include <ASCON.h>
#include <mbedtls/gcm.h>
#include <string.h>

#define TRIGGER_PIN    4
#define ITERATIONS     20000UL
#define PAYLOAD_BYTES  23
#define IDLE_MS        10000   // tempo para ler a tela entre casos
#define GAP_MS         200
#define PULSE_MS       100     // visivel a 500 ms/div
#define CONTROL_US     27      // ~ tempo da cifra Ascon de 23 B a 240 MHz

#define TAG_BYTES 16

static uint8_t key[ASCON128_KEY_SIZE];
static uint8_t nonce[ASCON128_NONCE_SIZE];
static uint8_t plaintext[PAYLOAD_BYTES];
static uint8_t asconCiphertext[PAYLOAD_BYTES + TAG_BYTES];
static uint8_t aesCiphertext[PAYLOAD_BYTES];
static uint8_t aesTag[TAG_BYTES];
static uint8_t output[PAYLOAD_BYTES + TAG_BYTES];

static mbedtls_gcm_context gcm;
static volatile int failures = 0;

// ---------------------------------------------------------------------------
// Uma operacao de cada caso. Todas escrevem em `output`, entao o compilador
// nao as remove.
// ---------------------------------------------------------------------------

static void runControl()
{
  delayMicroseconds(CONTROL_US);
}

static void runAsconEncrypt()
{
  size_t length = 0;
  ascon128a_aead_encrypt(output, &length, plaintext, PAYLOAD_BYTES, NULL, 0, nonce, key);
}

static void runAsconDecrypt()
{
  size_t length = 0;
  if (ascon128a_aead_decrypt(output, &length, asconCiphertext, sizeof(asconCiphertext),
                             NULL, 0, nonce, key) < 0) {
    failures++;
  }
}

static void runGcmEncrypt()
{
  if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, PAYLOAD_BYTES,
                                nonce, 12, NULL, 0, plaintext, output,
                                TAG_BYTES, output + PAYLOAD_BYTES) != 0) {
    failures++;
  }
}

static void runGcmDecrypt()
{
  if (mbedtls_gcm_auth_decrypt(&gcm, PAYLOAD_BYTES, nonce, 12, NULL, 0,
                               aesTag, TAG_BYTES, aesCiphertext, output) != 0) {
    failures++;
  }
}

struct Case {
  const char *name;
  int         pulses;
  void      (*run)(void);
};

static const Case cases[] = {
  { "controle (espera ocupada)", 1, runControl      },
  { "Ascon-128a cifra",          2, runAsconEncrypt },
  { "Ascon-128a decifra",        3, runAsconDecrypt },
  { "AES-128-GCM cifra",         4, runGcmEncrypt   },
  { "AES-128-GCM decifra",       5, runGcmDecrypt   },
};

static const int caseCount = sizeof(cases) / sizeof(cases[0]);

// ---------------------------------------------------------------------------

static void pulses(int count)
{
  for (int i = 0; i < count; i++) {
    digitalWrite(TRIGGER_PIN, HIGH);
    delay(PULSE_MS);
    digitalWrite(TRIGGER_PIN, LOW);
    delay(PULSE_MS);
  }
}

static void haltBlinking(const char *reason)
{
  Serial.print("AUTOTESTE FALHOU: ");
  Serial.println(reason);
  for (;;) {
    digitalWrite(TRIGGER_PIN, HIGH);
    delay(50);
    digitalWrite(TRIGGER_PIN, LOW);
    delay(50);
  }
}

static void prepareInputs()
{
  for (size_t i = 0; i < sizeof(key); i++)       { key[i]   = (uint8_t) i; }
  for (size_t i = 0; i < sizeof(nonce); i++)     { nonce[i] = (uint8_t)(0x10 + i); }
  for (size_t i = 0; i < sizeof(plaintext); i++) { plaintext[i] = (uint8_t)(0x20 + i); }

  // Textos cifrados validos, para que a decifragem percorra o caminho normal.
  size_t length = 0;
  ascon128a_aead_encrypt(asconCiphertext, &length, plaintext, PAYLOAD_BYTES, NULL, 0, nonce, key);

  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 128) != 0) {
    haltBlinking("gcm_setkey");
  }
  if (mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, PAYLOAD_BYTES, nonce, 12,
                                NULL, 0, plaintext, aesCiphertext, TAG_BYTES, aesTag) != 0) {
    haltBlinking("gcm_crypt_and_tag");
  }
}

static void selfCheck()
{
  size_t length = 0;

  if (ascon128a_aead_decrypt(output, &length, asconCiphertext, sizeof(asconCiphertext),
                             NULL, 0, nonce, key) < 0 ||
      length != PAYLOAD_BYTES || memcmp(output, plaintext, PAYLOAD_BYTES) != 0) {
    haltBlinking("Ascon decifra");
  }

  if (mbedtls_gcm_auth_decrypt(&gcm, PAYLOAD_BYTES, nonce, 12, NULL, 0,
                               aesTag, TAG_BYTES, aesCiphertext, output) != 0 ||
      memcmp(output, plaintext, PAYLOAD_BYTES) != 0) {
    haltBlinking("AES-GCM decifra");
  }
}

void setup()
{
  pinMode(TRIGGER_PIN, OUTPUT);
  digitalWrite(TRIGGER_PIN, LOW);

  Serial.begin(115200);
  delay(3000);

  prepareInputs();
  selfCheck();

  Serial.println();
  Serial.println("=== Energia por rajada: Ascon-128a x AES-128-GCM (Secao 3.4.4) ===");
  Serial.printf("payload %d B | %lu operacoes por rajada | repouso %d ms | GPIO %d\n",
                PAYLOAD_BYTES, ITERATIONS, IDLE_MS, TRIGGER_PIN);
  Serial.printf("CPU %u MHz | autoteste OK\n", (unsigned) getCpuFrequencyMhz());
  Serial.println("Desligue o USB para medir. Cada rajada termina com k pulsos: k = numero do caso.");
  Serial.println();
}

void loop()
{
  for (int c = 0; c < caseCount; c++) {
    delay(IDLE_MS);

    failures = 0;

    digitalWrite(TRIGGER_PIN, HIGH);
    uint32_t start = micros();
    for (uint32_t i = 0; i < ITERATIONS; i++) {
      cases[c].run();
    }
    uint32_t elapsed = micros() - start;
    digitalWrite(TRIGGER_PIN, LOW);

    delay(GAP_MS);
    pulses(cases[c].pulses);

    Serial.printf("[%d] %-27s rajada %lu us | %.2f us por operacao%s\n",
                  cases[c].pulses, cases[c].name, (unsigned long) elapsed,
                  elapsed / (double) ITERATIONS,
                  failures ? "  !! FALHAS NA DECIFRA" : "");
  }
  Serial.println();
}
