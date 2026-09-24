#include "aead_suite.h"

void setup()
{
  Serial.begin(115200);
  delay(300);

  aeadSuiteRun();
}

void loop()
{
  delay(1000);
}
