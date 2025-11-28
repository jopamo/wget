/* Download scheduler for wget
 * src/scheduler.h
 */

#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "wget.h"
#include "evloop.h"
#include "http-transaction.h"

/* Forward declarations */
struct download_job;
struct scheduler;

/* Job completion callback */
typedef void (*job_completion_cb)(struct download_job* job, bool success, void* user_data);

struct download_job {
  char* url;
  char* output_path;
  int retries_remaining;
  /* Additional job options/flags */
  bool recursive;
  bool timestamping;
  bool no_clobber;
  /* Range request support */
  wgint start_pos;
  /* Scheduler reference for retries */
  struct scheduler* scheduler;
  /* Retry timer */
  struct evloop_timer* retry_timer;
  /* Callback for job completion */
  job_completion_cb on_complete;
  void* user_data;
};

struct scheduler {
  struct ev_loop* loop;

  /* Job queues */
  struct download_job** pending_jobs;
  size_t pending_count;
  size_t pending_capacity;

  /* Active job count */
  size_t active_count;

  /* Host-based concurrency tracking */
  struct {
    char* host;
    int count;
  }* host_counts;
  size_t host_counts_size;
  size_t host_counts_capacity;

  /* Concurrency limits */
  int max_global;
  int max_per_host;

  /* Statistics */
  int completed_jobs;
  int failed_jobs;
  int total_jobs;
};

/* Scheduler API */
struct scheduler* scheduler_new(struct ev_loop* loop, int max_global, int max_per_host);
void scheduler_free(struct scheduler* s);

void scheduler_add_job(struct scheduler* s, struct download_job* job);
void scheduler_job_completed(struct scheduler* s, struct download_job* job, bool success);

/* Job management */
struct download_job* download_job_new(const char* url, const char* output_path);
void download_job_free(struct download_job* job);

/* Internal scheduling functions */
void scheduler_try_start_jobs(struct scheduler* s);
int scheduler_get_host_count(struct scheduler* s, const char* host);
void scheduler_update_host_count(struct scheduler* s, const char* host, int delta);

#endif /* SCHEDULER_H */