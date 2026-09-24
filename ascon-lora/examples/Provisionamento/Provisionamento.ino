// Rode UMA VEZ em cada no sensor, na bancada. O gateway nao passa por aqui.
//
// Na primeira vez a placa gera a propria chave e imprime o bloco que vai no
// Receptor. Rodar de novo so mostra a chave que ja existe. Depois, grave o
// Emissor por cima nesta mesma placa -- a chave fica guardada na NVS.

#include <AsconSecure.h>

void setup()
{
  Serial.begin(115200);
  delay(500);

  // asconSecureFactoryReset();   // descomente para descartar a chave e gerar outra

  // Nada de ADC, Wi-Fi ou Bluetooth antes desta linha: a geracao da chave usa o ADC.
  asconSecureLogTo(Serial);
  asconSecureProvision();
  asconSecurePrintProvisioning();
}

void loop()
{
  delay(1000);
}
