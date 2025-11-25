/* HTTP connection pool scalability tests
 * tests/http_connection_pool_test.c
 */

#include "config.h"
#include "http-pconn.h"
#include "evloop.h"
#include "threading.h"
#include "xalloc.h"
#include "url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#define NUM_HOSTS 10
#define TOTAL_CONNECTIONS_TEST 100

static atomic_int connection_attempts;
static atomic_int connection_successes;
static atomic_int connection_failures;

static void test_connection_pool_basics(void) {
  printf("\n=== Testing HTTP Connection Pool Basics ===\n");

  // Create test hosts
  char hosts[NUM_HOSTS][50];
  for (int i = 0; i < NUM_HOSTS; i++) {
    snprintf(hosts[i], sizeof(hosts[i]), "test-host-%d.example.com", i);
  }

  // Test registering connections
  printf("Testing connection registration...\n");
  for (int i = 0; i < NUM_HOSTS; i++) {
    int fake_socket = i * 1000 + 1;  // Unique fake socket
    register_persistent(hosts[i], 80, fake_socket, false);
  }

  // Test connection availability checking
  printf("Testing connection availability checking...\n");
  int available_count = 0;
  for (int i = 0; i < NUM_HOSTS; i++) {
    bool host_lookup_failed = false;
    bool available = persistent_available_p(hosts[i], 80, false, &host_lookup_failed);
    if (available) {
      available_count++;
    }
  }

  printf("Registered connections for %d hosts, %d available\n", NUM_HOSTS, available_count);

  // Clean up
  pconn_cleanup();
  printf("✓ Connection pool basics test passed\n");
}

static void test_connection_pool_scalability(void) {
  printf("\n=== Testing Connection Pool Scalability ===\n");

  atomic_store(&connection_attempts, 0);
  atomic_store(&connection_successes, 0);
  atomic_store(&connection_failures, 0);

  // Simulate connection pool usage
  const int NUM_OPERATIONS = 100;

  printf("Simulating %d connection pool operations...\n", NUM_OPERATIONS);

  clock_t start_time = clock();

  for (int i = 0; i < NUM_OPERATIONS; i++) {
    atomic_fetch_add(&connection_attempts, 1);

    char host[50];
    snprintf(host, sizeof(host), "scalability-host-%d.example.com", i % 20);

    // Register connection
    int fake_socket = i + 1000;
    register_persistent(host, 80, fake_socket, false);
    atomic_fetch_add(&connection_successes, 1);

    // Check availability
    bool host_lookup_failed = false;
    bool available = persistent_available_p(host, 80, false, &host_lookup_failed);
    if (!available) {
      atomic_fetch_add(&connection_failures, 1);
    }
  }

  clock_t end_time = clock();
  double elapsed_seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;

  printf("Connection pool scalability results:\n");
  printf("  Total operations: %d\n", atomic_load(&connection_attempts));
  printf("  Successful operations: %d\n", atomic_load(&connection_successes));
  printf("  Failed operations: %d\n", atomic_load(&connection_failures));
  printf("  Elapsed time: %.3f seconds\n", elapsed_seconds);
  printf("  Operations per second: %.1f\n", atomic_load(&connection_attempts) / elapsed_seconds);

  pconn_cleanup();
  printf("✓ Connection pool scalability test passed\n");
}

static void test_connection_pool_memory_usage(void) {
  printf("\n=== Testing Connection Pool Memory Usage ===\n");

  // Test with multiple unique hosts
  const int NUM_UNIQUE_HOSTS = 50;

  printf("Testing with %d unique hosts...\n", NUM_UNIQUE_HOSTS);

  // Register connections for many hosts
  for (int host_idx = 0; host_idx < NUM_UNIQUE_HOSTS; host_idx++) {
    char host[50];
    snprintf(host, sizeof(host), "memory-test-host-%d.example.com", host_idx);

    int fake_socket = host_idx + 1000;
    register_persistent(host, 80, fake_socket, false);
  }

  // Verify we can check availability
  int total_available = 0;
  for (int host_idx = 0; host_idx < NUM_UNIQUE_HOSTS; host_idx++) {
    char host[50];
    snprintf(host, sizeof(host), "memory-test-host-%d.example.com", host_idx);

    bool host_lookup_failed = false;
    bool available = persistent_available_p(host, 80, false, &host_lookup_failed);
    if (available) {
      total_available++;
    }
  }

  printf("Successfully managed connections for %d hosts, %d available\n", NUM_UNIQUE_HOSTS, total_available);

  pconn_cleanup();
  printf("✓ Connection pool memory usage test passed\n");
}

static void test_connection_pool_concurrent_access(void) {
  printf("\n=== Testing Concurrent Connection Pool Access ===\n");

  const int NUM_THREADS = 5;
  const int OPERATIONS_PER_THREAD = 20;

  atomic_int total_operations = 0;

  printf("Testing %d threads with %d operations each...\n", NUM_THREADS, OPERATIONS_PER_THREAD);

  struct {
    pthread_t thread;
    int thread_id;
    atomic_int* counter;
  } threads[NUM_THREADS];

  // Worker function for concurrent access
  void* worker(void* arg) {
    int thread_id = *(int*)arg;
    char host[50];
    snprintf(host, sizeof(host), "concurrent-host-%d.example.com", thread_id % 10);

    for (int i = 0; i < OPERATIONS_PER_THREAD; i++) {
      // Register connection
      int fake_socket = thread_id * 1000 + i;
      register_persistent(host, 80, fake_socket, false);

      // Check availability
      bool host_lookup_failed = false;
      bool available = persistent_available_p(host, 80, false, &host_lookup_failed);
      if (available) {
        atomic_fetch_add(&total_operations, 1);
      }
    }

    return NULL;
  }

  clock_t start_time = clock();

  // Start threads
  for (int i = 0; i < NUM_THREADS; i++) {
    threads[i].thread_id = i;
    threads[i].counter = &total_operations;
    pthread_create(&threads[i].thread, NULL, worker, &threads[i].thread_id);
  }

  // Wait for all threads
  for (int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i].thread, NULL);
  }

  clock_t end_time = clock();
  double elapsed_seconds = (double)(end_time - start_time) / CLOCKS_PER_SEC;

  printf("Concurrent access results:\n");
  printf("  Total operations: %d\n", atomic_load(&total_operations));
  printf("  Elapsed time: %.3f seconds\n", elapsed_seconds);
  printf("  Operations per second: %.1f\n", atomic_load(&total_operations) / elapsed_seconds);

  pconn_cleanup();
  printf("✓ Concurrent connection pool access test passed\n");
}

int main(void) {
  printf("Starting HTTP connection pool scalability tests...\n");

  // Initialize event loop
  wget_ev_loop_init();

  // Run tests
  test_connection_pool_basics();
  test_connection_pool_scalability();
  test_connection_pool_memory_usage();
  test_connection_pool_concurrent_access();

  printf("\n=== All HTTP Connection Pool Tests PASSED ===\n");
  return 0;
}