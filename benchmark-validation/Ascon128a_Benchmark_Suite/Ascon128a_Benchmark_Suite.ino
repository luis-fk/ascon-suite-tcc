#include "bench_suite.h"

void setup()
{
  Serial.begin(115200);
  delay(300);

  benchSuiteRun();
}

void loop()
{
  delay(1000);
}
