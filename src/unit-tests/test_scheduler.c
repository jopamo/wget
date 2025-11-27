/* Unit test for scheduler functionality
 * src/unit-tests/test_scheduler.c
 */

#include "wget.h"
#include "scheduler.h"
#include "evloop.h"
#include "utils.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Globals required by wget_lib linkage */
struct options opt;
const char* exec_name = "unit-scheduler";
const char* program_name = "unit-scheduler";
const char* program_argstring = "unit-scheduler";

#ifdef HAVE_LIBCARES
#include <ares.h>
ares_channel ares;
#else
void* ares;
#endif

/* Test completion callback counters */
static int test_completed_jobs = 0;
static int test_failed_jobs = 0;

static void test_job_completion_callback(struct download_job* job, bool success, void* user_data) {
  (void)job;
  (void)user_data;

  if (success) {
    test_completed_jobs++;
  }
  else {
    test_failed_jobs++;
  }
}

static void test_basic_scheduler_functionality(void) {
  printf("Test 1: Basic scheduler functionality...\n");

  struct ev_loop* loop = evloop_get_default();
  struct scheduler* sched = scheduler_new(loop, 2, 1); /* max_global=2, max_per_host=1 */

  assert(sched != NULL);
  assert(sched->pending_count == 0);
  assert(sched->active_count == 0);
  assert(sched->total_jobs == 0);

  /* Create test jobs */
  struct download_job* job1 = download_job_new("http://example.com/file1.txt", "file1.txt");
  struct download_job* job2 = download_job_new("http://example.com/file2.txt", "file2.txt");
  struct download_job* job3 = download_job_new("http://test.com/file3.txt", "file3.txt");

  assert(job1 != NULL);
  assert(job2 != NULL);
  assert(job3 != NULL);

  /* Set completion callbacks */
  job1->on_complete = test_job_completion_callback;
  job2->on_complete = test_job_completion_callback;
  job3->on_complete = test_job_completion_callback;

  /* Add jobs to scheduler */
  scheduler_add_job(sched, job1);
  scheduler_add_job(sched, job2);
  scheduler_add_job(sched, job3);

  /* Verify scheduler state */
  assert(sched->total_jobs == 3);
  assert(sched->pending_count == 1); /* 2 started, 1 pending due to per-host limit */
  assert(sched->active_count == 2);

  /* Simulate job completions */
  scheduler_job_completed(sched, job1, true);
  assert(sched->active_count == 1);
  assert(sched->pending_count == 0); /* Third job should start */

  scheduler_job_completed(sched, job2, true);
  scheduler_job_completed(sched, job3, true);

  /* Verify final state */
  assert(sched->pending_count == 0);
  assert(sched->active_count == 0);
  assert(sched->completed_jobs == 3);
  assert(sched->failed_jobs == 0);
  assert(test_completed_jobs == 3);
  assert(test_failed_jobs == 0);

  scheduler_free(sched);
  printf("Test 1: PASSED\n");
}

static void test_retry_functionality(void) {
  printf("Test 2: Retry functionality...\n");

  struct ev_loop* loop = evloop_get_default();
  struct scheduler* sched = scheduler_new(loop, 1, 1);

  /* Create a job with retries */
  struct download_job* job = download_job_new("http://example.com/failing.txt", "failing.txt");
  job->on_complete = test_job_completion_callback;

  scheduler_add_job(sched, job);

  /* Simulate initial failure */
  scheduler_job_completed(sched, job, false);

  /* Job should be scheduled for retry */
  assert(job->retries_remaining == 2); /* Started with 3, now 2 */
  assert(sched->pending_count == 1);   /* Job should be back in pending for retry */
  assert(sched->active_count == 0);

  /* Simulate retry success */
  scheduler_job_completed(sched, job, true);

  assert(sched->completed_jobs == 1);
  assert(sched->failed_jobs == 0);
  assert(test_completed_jobs == 1);

  scheduler_free(sched);
  printf("Test 2: PASSED\n");
}

static void test_concurrency_limits(void) {
  printf("Test 3: Concurrency limits...\n");

  struct ev_loop* loop = evloop_get_default();
  struct scheduler* sched = scheduler_new(loop, 1, 1); /* Strict limits */

  /* Create multiple jobs for same host */
  struct download_job* job1 = download_job_new("http://example.com/file1.txt", "file1.txt");
  struct download_job* job2 = download_job_new("http://example.com/file2.txt", "file2.txt");

  scheduler_add_job(sched, job1);
  scheduler_add_job(sched, job2);

  /* Only one job should be active due to per-host limit */
  assert(sched->active_count == 1);
  assert(sched->pending_count == 1);

  /* Complete first job, second should start */
  scheduler_job_completed(sched, job1, true);
  assert(sched->active_count == 1);
  assert(sched->pending_count == 0);

  scheduler_job_completed(sched, job2, true);

  assert(sched->active_count == 0);
  assert(sched->pending_count == 0);

  scheduler_free(sched);
  printf("Test 3: PASSED\n");
}

int main(void) {
  printf("Running scheduler unit tests...\n\n");

  /* Reset counters */
  test_completed_jobs = 0;
  test_failed_jobs = 0;

  test_basic_scheduler_functionality();

  /* Reset counters for next test */
  test_completed_jobs = 0;
  test_failed_jobs = 0;

  test_retry_functionality();

  /* Reset counters for next test */
  test_completed_jobs = 0;
  test_failed_jobs = 0;

  test_concurrency_limits();

  printf("\nAll scheduler unit tests PASSED!\n");
  return 0;
}