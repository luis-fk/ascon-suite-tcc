// No sensor. Grave depois de rodar o Provisionamento nesta mesma placa.
//
// Deixe "Ferramentas -> Erase All Flash Before Sketch Upload" em Disabled:
// ligado, ele apaga a chave, e o Begin passa a dizer que a placa nao foi
// provisionada.

#include <AsconSecure.h>

void setup()
{
  Serial.begin(115200);
  asconSecureLogTo(Serial);
  asconSecureBegin();

  // ---- LoRa: inicialize o radio aqui ----
}

void loop()
{
  AsconPacket pacote = asconSecurePack("temp=23.5C;lux=00812;batt=98");

  if (pacote) {
    // ---- LoRa: transmita pacote.length bytes de pacote.data ----
  }

  delay(15000);
}
