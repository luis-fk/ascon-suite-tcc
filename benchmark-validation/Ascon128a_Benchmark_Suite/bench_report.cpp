#include "bench_report.h"

static int problemCount = 0;
static int noteCount    = 0;

void reportProblem(const char *message)
{
  problemCount++;
  Serial.print("  PROBLEMA: ");
  Serial.println(message);
}

void reportNote(const char *message)
{
  noteCount++;
  Serial.print("  RESSALVA: ");
  Serial.println(message);
}

int reportProblemCount() { return problemCount; }
int reportNoteCount()    { return noteCount; }

void reportCrossRunLine(const char *label, const CrossRun *summary)
{
  double meanFloor = summary->sumFloors / summary->runs;

  Serial.printf("      %s: piso min %u | piso max %u | spread %u | media dos pisos %.1f (%.2f us) | execucoes no piso %d/%d | desvio medio dentro da execucao %.2f\n",
                label,
                (unsigned) summary->minFloor, (unsigned) summary->maxFloor,
                (unsigned) (summary->maxFloor - summary->minFloor),
                meanFloor, benchCyclesToMicroseconds(meanFloor),
                summary->runsAtFloor, summary->runs,
                summary->sumStandardDeviation / summary->runs);
}

void reportStatsLine(const char *label, const CycleStats *stats)
{
  Serial.printf("      %s: piso %u | media %.2f | max %u | desvio %.2f | spread %u ciclos\n",
                label, (unsigned) stats->minCycles, stats->meanCycles,
                (unsigned) stats->maxCycles, stats->standardDeviation,
                (unsigned) (stats->maxCycles - stats->minCycles));
}

double reportSlopePerBlock(uint32_t floor16, uint32_t floor64)
{
  return ((double) floor64 - (double) floor16) / 3.0;
}

double reportLinearityPercent(uint32_t floor16, uint32_t floor32, uint32_t floor64)
{
  double predicted32 = (double) floor16 + reportSlopePerBlock(floor16, floor64);

  if (predicted32 == 0.0) { return 0.0; }

  double difference = (double) floor32 - predicted32;
  if (difference < 0.0) { difference = -difference; }

  return 100.0 * difference / predicted32;
}
