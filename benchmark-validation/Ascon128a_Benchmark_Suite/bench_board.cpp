#include "bench_board.h"
#include "bench_config.h"

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

void boardReport()
{
  Serial.println("[0] Identificacao do build");

#ifdef CONFIG_IDF_TARGET
  Serial.print("  Alvo (CONFIG_IDF_TARGET)   : "); Serial.println(CONFIG_IDF_TARGET);
#else
  Serial.println("  Alvo (CONFIG_IDF_TARGET)   : nao definido");
#endif

#ifdef IDF_VERSION_REACHED
  Serial.printf("  ESP-IDF                    : %d.%d.%d\n",
                ESP_IDF_VERSION_MAJOR, ESP_IDF_VERSION_MINOR, ESP_IDF_VERSION_PATCH);
#else
  Serial.println("  ESP-IDF                    : esp_idf_version.h nao alcancado");
#endif

#ifdef ARDUINO_VERSION_REACHED
  Serial.printf("  Core arduino-esp32         : %d.%d.%d\n",
                ESP_ARDUINO_VERSION_MAJOR, ESP_ARDUINO_VERSION_MINOR, ESP_ARDUINO_VERSION_PATCH);
#else
  Serial.println("  Core arduino-esp32         : esp_arduino_version.h nao alcancado");
#endif

  Serial.printf("  Chip                       : %s rev %u, %u nucleo(s), CPU a %u MHz\n",
                ESP.getChipModel(), (unsigned) ESP.getChipRevision(),
                (unsigned) ESP.getChipCores(), (unsigned) getCpuFrequencyMhz());
  Serial.printf("  Flash                      : chip de %u bytes | sketch %u bytes | espaco livre para sketch %u bytes\n",
                (unsigned) ESP.getFlashChipSize(), (unsigned) ESP.getSketchSize(),
                (unsigned) ESP.getFreeSketchSpace());
  Serial.printf("  Estado do Ascon-128a       : %u bytes (ascon128a_state_t)\n",
                (unsigned) sizeof(ascon128a_state_t));
  Serial.printf("  Execucoes por tamanho      : %d | medidas por execucao: %d | aquecimento: %d\n",
                RUNS, ITERATIONS, WARMUP);

  Serial.print("  Tamanhos de payload (bytes): ");
  for (size_t index = 0; index < SIZE_COUNT; index++) {
    Serial.print((unsigned) payloadSizes[index]);
    Serial.print(index + 1 < SIZE_COUNT ? ", " : "\n");
  }
  Serial.println();
}
