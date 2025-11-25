/* Performance benchmarks for event-driven architecture
 * tests/performance_benchmark_test.c
 */

#include "config.h"
#include "evloop.h"
#include "scheduler.h"
#include "transfer.h"
#include "threading.h"
#include "xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>

#define BENCHMARK_ITERATIONS 3

static void print_memory_usage(const char* label) {
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    printf("%s - Memory: RSS=%.1fMB\n", label, (double)usage.ru_maxrss / 1024.0);
  }
}

static void async_task_counter_callback(void* arg) {
  atomic_int* counter = (atomic_int*)arg;
  atomic_fetch_add(counter, 1);
}

static void benchmark_event_loop_latency(void) {
  printf("\n=== Benchmarking Event Loop Latency ===\n");

  struct ev_loop* loop = wget_ev_loop_get();
  const int NUM_TASKS = 10000;

  atomic_int completed_tasks = 0;
  struct timespec start_time, end_time;

  clock_gettime(CLOCK_MONOTONIC, &start_time);

  for (int i = 0; i < NUM_TASKS; i++) {
    wget_ev_loop_post_async(async_task_counter_callback, &completed_tasks);
  }

  // Run until all tasks complete
  while (atomic_load(&completed_tasks) < NUM_TASKS) {
    wget_ev_loop_run_once();
  }

  clock_gettime(CLOCK_MONOTONIC, &end_time);

  double elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1e9 + (end_time.tv_nsec - start_time.tv_nsec);
  double elapsed_ms = elapsed_ns / 1e6;

  printf("Event loop latency results:\n");
  printf("  Tasks processed: %d\n", NUM_TASKS);
  printf("  Total time: %.3f ms\n", elapsed_ms);
  printf("  Average latency per task: %.3f µs\n", (elapsed_ms * 1000) / NUM_TASKS);
  printf("  Throughput: %.1f tasks/ms\n", NUM_TASKS / elapsed_ms);

  assert(atomic_load(&completed_tasks) == NUM_TASKS);
}

static void scheduler_transfer_complete_cb(transfer_ctx_t* ctx, void* user_arg, int status) {
  atomic_int* counter = (atomic_int*)ctx->user_priority;  // Hack: reuse field
  atomic_fetch_add(counter, 1);
  transfer_context_free(ctx);
}

static void benchmark_scheduler_throughput(void) {
  printf("\n=== Benchmarking Scheduler Throughput ===\n");

  struct ev_loop* loop = wget_ev_loop_get();

  // Test different concurrency levels
  size_t concurrency_levels[] = {10, 50, 100, 500, 1000};
  size_t num_levels = sizeof(concurrency_levels) / sizeof(concurrency_levels[0]);

  for (size_t level_idx = 0; level_idx < num_levels; level_idx++) {
    size_t max_concurrent = concurrency_levels[level_idx];
    size_t total_transfers = max_concurrent * 10;  // 10x the concurrency limit

    printf("\nTesting concurrency level: %zu (total transfers: %zu)\n", max_concurrent, total_transfers);

    scheduler_t* sched = scheduler_create(loop, max_concurrent);
    assert(sched != NULL);

    atomic_int completed = 0;
    struct timespec start_time, end_time;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // Enqueue all transfers
    for (size_t i = 0; i < total_transfers; i++) {
      transfer_ctx_t* ctx = xcalloc(1, sizeof(transfer_ctx_t));
      transfer_context_init(ctx);
      transfer_context_bind_loop(ctx, loop);
      ctx->user_priority = (int)&completed;  // Store counter pointer

      int result = scheduler_enqueue(sched, ctx, 0, scheduler_transfer_complete_cb, NULL);
      assert(result == 0);
    }

    // Wait for completion
    while (atomic_load(&completed) < total_transfers) {
      wget_ev_loop_run_once();
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);

    double elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1e9 + (end_time.tv_nsec - start_time.tv_nsec);
    double elapsed_ms = elapsed_ns / 1e6;

    printf("  Level %zu: %zu transfers in %.3f ms (%.1f transfers/ms)\n", max_concurrent, total_transfers, elapsed_ms, total_transfers / elapsed_ms);

    scheduler_destroy(sched, false);
  }
}

static void benchmark_memory_scalability(void) {
  printf("\n=== Benchmarking Memory Scalability ===\n");

  print_memory_usage("Initial state");

  struct ev_loop* loop = wget_ev_loop_get();

  // Test memory usage with increasing number of concurrent transfers
  size_t transfer_counts[] = {100, 500, 1000, 2000};
  size_t num_counts = sizeof(transfer_counts) / sizeof(transfer_counts[0]);

  for (size_t count_idx = 0; count_idx < num_counts; count_idx++) {
    size_t num_transfers = transfer_counts[count_idx];

    scheduler_t* sched = scheduler_create(loop, num_transfers);
    assert(sched != NULL);

    atomic_int completed = 0;

    // Create and enqueue transfers
    for (size_t i = 0; i < num_transfers; i++) {
      transfer_ctx_t* ctx = xcalloc(1, sizeof(transfer_ctx_t));
      transfer_context_init(ctx);
      transfer_context_bind_loop(ctx, loop);
      ctx->user_priority = (int)&completed;  // Store counter pointer

      int result = scheduler_enqueue(sched, ctx, 0, scheduler_transfer_complete_cb, NULL);
      assert(result == 0);
    }

    // Wait briefly to let some transfers start
    for (int i = 0; i < 10 && atomic_load(&completed) < num_transfers; i++) {
      wget_ev_loop_run_once();
    }

    char label[100];
    snprintf(label, sizeof(label), "With %zu concurrent transfers", num_transfers);
    print_memory_usage(label);

    // Clean up
    scheduler_destroy(sched, false);
  }

  print_memory_usage("After cleanup");
}

static void benchmark_concurrent_timer_performance(void) {
  printf("\n=== Benchmarking Concurrent Timer Performance ===\n");
  printf("Timer benchmark not implemented - requires direct libev timer integration\n");
}

static void thread_pool_worker(void* arg) {
  // Simulate some work
  for (int j = 0; j < 1000; j++) { /* busy work */
  }

  atomic_int* counter = (atomic_int*)arg;
  atomic_fetch_add(counter, 1);
}

static void benchmark_thread_pool_performance(void) {
  printf("\n=== Benchmarking Thread Pool Performance ===\n");

#ifdef WGET_THREAD_POOL_AVAILABLE
  const int NUM_TASKS = 1000;
  atomic_int completed_tasks = 0;
  struct timespec start_time, end_time;

  printf("Submitting %d tasks to thread pool...\n", NUM_TASKS);

  clock_gettime(CLOCK_MONOTONIC, &start_time);

  // Submit tasks to thread pool
  for (int i = 0; i < NUM_TASKS; i++) {
    wget_thread_pool_submit(thread_pool_worker, &completed_tasks);
  }

  // Wait for completion
  while (atomic_load(&completed_tasks) < NUM_TASKS) {
    usleep(1000);  // 1ms sleep
  }

  clock_gettime(CLOCK_MONOTONIC, &end_time);

  double elapsed_ns = (end_time.tv_sec - start_time.tv_sec) * 1e9 + (end_time.tv_nsec - start_time.tv_nsec);
  double elapsed_ms = elapsed_ns / 1e6;

  printf("Thread pool performance results:\n");
  printf("  Tasks completed: %d\n", NUM_TASKS);
  printf("  Total time: %.3f ms\n", elapsed_ms);
  printf("  Average time per task: %.3f µs\n", (elapsed_ms * 1000) / NUM_TASKS);
  printf("  Task throughput: %.1f tasks/ms\n", NUM_TASKS / elapsed_ms);

  assert(atomic_load(&completed_tasks) == NUM_TASKS);
#else
  printf("Thread pool not available in this build, skipping test\n");
#endif
}

int main(void) {
  printf("Starting performance benchmarks...\n");

  // Initialize event loop
  wget_ev_loop_init();

  // Run benchmarks multiple times for consistency
  for (int iteration = 0; iteration < BENCHMARK_ITERATIONS; iteration++) {
    printf("\n=== Benchmark Iteration %d/%d ===\n", iteration + 1, BENCHMARK_ITERATIONS);

    benchmark_event_loop_latency();
    benchmark_scheduler_throughput();
    benchmark_memory_scalability();
    benchmark_concurrent_timer_performance();
    benchmark_thread_pool_performance();
  }

  printf("\n=== All Performance Benchmarks COMPLETED ===\n");
  return 0;
}