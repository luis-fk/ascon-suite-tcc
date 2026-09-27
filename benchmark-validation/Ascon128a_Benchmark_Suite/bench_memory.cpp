#include "bench_memory.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define WATCHER_CORE      0      // a tarefa do Arduino roda no nucleo 1
#define WATCHER_PRIORITY  5
#define WATCHER_STACK     2048

struct HeapWatcher {
  volatile bool     started;
  volatile bool     stop;
  volatile bool     finished;
  volatile uint32_t minimumFree;
  volatile uint32_t samples;
};

static HeapWatcher watcher;

static void heapWatcherTask(void *)
{
  watcher.minimumFree = 0xFFFFFFFFu;
  watcher.samples     = 0;
  watcher.started     = true;

  while (!watcher.stop) {
    uint32_t freeNow = ESP.getFreeHeap();
    if (freeNow < watcher.minimumFree) { watcher.minimumFree = freeNow; }
    watcher.samples++;
  }

  watcher.finished = true;
  vTaskDelete(NULL);
}

HeapProbe memoryHeapProbe(const BenchSpec *spec, size_t length)
{
  HeapProbe probe;

  watcher.started  = false;
  watcher.stop     = false;
  watcher.finished = false;

  BaseType_t created = xTaskCreatePinnedToCore(heapWatcherTask, "bench_heapwatch",
                                               WATCHER_STACK, NULL, WATCHER_PRIORITY,
                                               NULL, WATCHER_CORE);
  probe.watched = (created == pdPASS);

  for (int waited = 0; probe.watched && waited < 1000 && !watcher.started; waited++) {
    delay(1);
  }
  probe.watched = probe.watched && watcher.started;

  probe.freeBefore = ESP.getFreeHeap();

  if (spec->beginRun != NULL) { spec->beginRun(length); }
  spec->prepare(0, length);
  spec->operation(length);
  if (spec->endRun != NULL) { spec->endRun(length); }

  probe.freeAfter = ESP.getFreeHeap();

  watcher.stop = true;

  for (int waited = 0; probe.watched && waited < 1000 && !watcher.finished; waited++) {
    delay(1);
  }

  probe.samples       = watcher.samples;
  probe.minimumDuring = (probe.watched && watcher.samples > 0) ? watcher.minimumFree : probe.freeBefore;

  delay(10);   // deixa a tarefa terminar de se apagar antes da proxima
  return probe;
}

static void stackProbeTask(void *argument)
{
  StackProbe *probe = (StackProbe *) argument;

  probe->markStart = uxTaskGetStackHighWaterMark(NULL);

  if (probe->spec->beginRun != NULL) { probe->spec->beginRun(probe->length); }

  for (int iteration = 0; iteration < 8; iteration++) {
    probe->spec->prepare(iteration, probe->length);
    probe->spec->operation(probe->length);
  }

  if (probe->spec->endRun != NULL) { probe->spec->endRun(probe->length); }

  probe->markEnd = uxTaskGetStackHighWaterMark(NULL);
  probe->done    = true;

  vTaskDelete(NULL);
}

bool memoryStackProbe(const BenchSpec *spec, size_t length, StackProbe *probe)
{
  probe->spec      = spec;
  probe->length    = length;
  probe->markStart = 0;
  probe->markEnd   = 0;
  probe->done      = false;

  BaseType_t created = xTaskCreatePinnedToCore(stackProbeTask, "bench_probe",
                                               PROBE_TASK_STACK_BYTES, probe,
                                               1, NULL, 1);
  if (created != pdPASS) { return false; }

  for (int waited = 0; waited < 5000 && !probe->done; waited++) {
    delay(1);
  }

  delay(10);   // deixa a tarefa terminar de se apagar antes da proxima
  return probe->done;
}
