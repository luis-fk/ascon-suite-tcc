#include "AsconSecureInterno.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <bootloader_random.h>

using namespace ascon_interno;

static bool keyJustGenerated = false;

// Com Wi-Fi e Bluetooth desligados, o gerador de hardware do ESP32 nao tem
// fonte de entropia de verdade. bootloader_random_enable() liga o SAR ADC como
// fonte -- e e por isso que o provisionamento precisa vir antes de qualquer
// uso do ADC ou do radio interno.
//
// A personalizacao leva o eFuse MAC, gravado de fabrica em cada chip: mesmo
// com entropia ruim, duas placas nao chegam a mesma chave.
static AsconSecureStatus randomBytes(uint8_t *out, size_t length)
{
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context drbg;
  AsconSecureStatus        status = ASCON_SECURE_OK;

  bootloader_random_enable();

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);

  uint8_t  personalization[16];
  uint64_t chipId = ESP.getEfuseMac();

  memcpy(personalization, "ascon-lora", 10);
  for (int i = 0; i < 6; i++) {
    personalization[10 + i] = (uint8_t)(chipId >> (8 * i));
  }

  if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                            personalization, sizeof(personalization)) != 0) {
    status = ASCON_SECURE_ERR_RNG;
  }
  else if (mbedtls_ctr_drbg_random(&drbg, out, length) != 0) {
    status = ASCON_SECURE_ERR_RNG;
  }

  mbedtls_ctr_drbg_free(&drbg);
  mbedtls_entropy_free(&entropy);
  bootloader_random_disable();

  return status;
}

static AsconSecureStatus provisionImpl()
{
  keyJustGenerated = false;

  Preferences nvs;

  if (!nvs.begin(NVS_SENDER, false)) {
    return ASCON_SECURE_ERR_NVS;
  }

  if (!nvs.isKey(NVS_KEY)) {
    uint8_t material[ASCON_SECURE_KEY_BYTES + ASCON_SECURE_PREFIX_BYTES];

    AsconSecureStatus status = randomBytes(material, sizeof(material));

    if (status != ASCON_SECURE_OK) {
      nvs.end();
      return status;
    }

    // A chave e gravada por ultimo e serve de marca de provisionamento
    // completo. Se faltar energia no meio, nao existe chave, nada foi cifrado
    // com ela, e rodar o provisionamento de novo gera tudo outra vez.
    bool written =
      nvs.putBytes(NVS_PREFIX, material + ASCON_SECURE_KEY_BYTES,
                   ASCON_SECURE_PREFIX_BYTES) == ASCON_SECURE_PREFIX_BYTES &&
      nvs.putUInt(NVS_RESERVED, COUNTER_WINDOW) != 0 &&
      nvs.putBytes(NVS_KEY, material, ASCON_SECURE_KEY_BYTES) == ASCON_SECURE_KEY_BYTES;

    secureZero(material, sizeof(material));

    if (!written) {
      nvs.end();
      return ASCON_SECURE_ERR_NVS;
    }

    keyJustGenerated = true;
  }

  nvs.end();

  return loadSenderState();
}

AsconSecureStatus asconSecureProvision()
{
  AsconSecureStatus status = provisionImpl();
  logStatus("provisionamento falhou", -1, status);

  if (status == ASCON_SECURE_OK && keyJustGenerated && logSink != NULL) {
    logSink->println("asconSecure: chave NOVA gerada nesta placa. O Receptor so reconhece");
    logSink->println("asconSecure: este no depois de receber o bloco de asconSecurePrintProvisioning().");
  }

  return status;
}

// Oito bytes por linha, ja no formato de inicializador de C.
static void printByteArray(const char *name, const char *sizeMacro,
                           const uint8_t *data, size_t length)
{
  Serial.printf("static const uint8_t %s[%s] = {\n", name, sizeMacro);

  for (size_t i = 0; i < length; i++) {
    if (i % 8 == 0) { Serial.print("  "); }

    Serial.printf("0x%02x", data[i]);

    if (i + 1 < length) { Serial.print(","); }
    if (i % 8 == 7 || i + 1 == length) { Serial.println(); }
    else { Serial.print(" "); }
  }

  Serial.println("};");
}

void asconSecurePrintProvisioning()
{
  if (!senderReady) {
    Serial.println("asconSecure: chave indisponivel -- o provisionamento nao foi feito ou falhou.");
    return;
  }

  uint64_t chipId = ESP.getEfuseMac();

  Serial.println();
  Serial.println("=== Provisionamento (segredo na serial: use so em bancada) ===");

  // Para nao trocar os blocos entre as placas quando provisionar varias seguidas.
  Serial.print("Placa (eFuse MAC): ");
  for (int i = 5; i >= 0; i--) {
    Serial.printf("%02X", (uint8_t)(chipId >> (8 * i)));
  }
  Serial.println();
  Serial.printf("Contador atual   : %u\n", (unsigned) senderCounter);

  Serial.println();
  Serial.println("--- 8< --- cole daqui para baixo no sketch do Receptor --- 8< ---");
  Serial.println();
  Serial.println("#define NO_SENSOR 1   // escolha um id unico por no (1..255)");
  Serial.println();

  printByteArray("chaveNo", "ASCON_SECURE_KEY_BYTES", senderKey, ASCON_SECURE_KEY_BYTES);
  Serial.println();
  printByteArray("prefixoNo", "ASCON_SECURE_PREFIX_BYTES", senderPrefix, ASCON_SECURE_PREFIX_BYTES);

  Serial.println();
  Serial.println("--- 8< --- fim --- 8< ---");
  Serial.println();
  Serial.println("No setup() do Receptor:");
  Serial.println("  asconSecureAddPeer(NO_SENSOR, chaveNo, prefixoNo);");
  Serial.println();
}

static AsconSecureStatus factoryResetImpl()
{
  Preferences nvs;

  if (!nvs.begin(NVS_SENDER, false)) {
    return ASCON_SECURE_ERR_NVS;
  }

  if (!nvs.clear()) {
    nvs.end();
    return ASCON_SECURE_ERR_NVS;
  }

  nvs.end();

  secureZero(senderKey, sizeof(senderKey));
  secureZero(senderPrefix, sizeof(senderPrefix));
  senderCounter  = 0;
  senderReserved = 0;
  senderReady    = false;

  return ASCON_SECURE_OK;
}

AsconSecureStatus asconSecureFactoryReset()
{
  AsconSecureStatus status = factoryResetImpl();
  logStatus("FactoryReset falhou, a chave ANTIGA continua em uso", -1, status);
  return status;
}
