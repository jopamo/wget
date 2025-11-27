/* Download scheduler for wget
 * src/scheduler.c
 */

#include "scheduler.h"
#include "url.h"
#include "utils.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define INITIAL_CAPACITY 16
#define HOST_COUNTS_INITIAL_CAPACITY 32

/* Internal helper functions */
static void scheduler_grow_pending(struct scheduler* s);
static void scheduler_grow_host_counts(struct scheduler* s);
static const char* extract_host_from_url(const char* url);
static void scheduler_retry_callback(void* arg);

struct scheduler* scheduler_new(struct ev_loop* loop, int max_global, int max_per_host) {
  struct scheduler* s = xmalloc(sizeof(struct scheduler));

  s->loop = loop;
  s->max_global = max_global;
  s->max_per_host = max_per_host;

  /* Initialize pending jobs array */
  s->pending_jobs = xmalloc(INITIAL_CAPACITY * sizeof(struct download_job*));
  s->pending_count = 0;
  s->pending_capacity = INITIAL_CAPACITY;

  /* Initialize active count */
  s->active_count = 0;

  /* Initialize host counts */
  s->host_counts = xmalloc(HOST_COUNTS_INITIAL_CAPACITY * sizeof(*s->host_counts));
  s->host_counts_size = 0;
  s->host_counts_capacity = HOST_COUNTS_INITIAL_CAPACITY;

  /* Initialize statistics */
  s->completed_jobs = 0;
  s->failed_jobs = 0;
  s->total_jobs = 0;

  return s;
}

void scheduler_free(struct scheduler* s) {
  if (!s)
    return;

  /* Free pending jobs */
  for (size_t i = 0; i < s->pending_count; i++) {
    download_job_free(s->pending_jobs[i]);
  }
  free(s->pending_jobs);

  /* Free host counts */
  for (size_t i = 0; i < s->host_counts_size; i++) {
    free(s->host_counts[i].host);
  }
  free(s->host_counts);

  free(s);
}

void scheduler_add_job(struct scheduler* s, struct download_job* job) {
  if (s->pending_count >= s->pending_capacity) {
    scheduler_grow_pending(s);
  }

  /* Set scheduler reference for retry handling */
  job->scheduler = s;

  s->pending_jobs[s->pending_count++] = job;
  s->total_jobs++;

  DEBUGP(("[scheduler] Added job: %s -> %s\n", job->url, job->output_path));

  /* Try to start new jobs */
  scheduler_try_start_jobs(s);
}

void scheduler_job_completed(struct scheduler* s, struct download_job* job, bool success) {
  /* Update active count */
  if (s->active_count > 0) {
    s->active_count--;
  }

  /* Handle retry logic for failed jobs */
  if (!success && job->retries_remaining > 0) {
    /* Schedule a retry with exponential backoff */
    job->retries_remaining--;

    /* Calculate backoff delay (exponential: 1, 2, 4, 8 seconds) */
    double backoff_delay = 1.0 * (1 << (3 - job->retries_remaining));

    DEBUGP(("[scheduler] Scheduling retry for %s in %.1f seconds (retries left: %d)\n", job->url, backoff_delay, job->retries_remaining));

    /* Create retry timer */
    struct evloop_timer* retry_timer = evloop_timer_start(s->loop, backoff_delay, 0.0, scheduler_retry_callback, job);

    /* Store timer in job for potential cancellation */
    job->retry_timer = retry_timer;

    /* Update host count since we're no longer active */
    const char* host = extract_host_from_url(job->url);
    if (host) {
      scheduler_update_host_count(s, host, -1);
    }

    /* Don't mark as failed yet - we're retrying */
    goto try_start_new_jobs;
  }

  /* Update statistics */
  if (success) {
    s->completed_jobs++;
  }
  else {
    s->failed_jobs++;
  }

  /* Update host count for completed/failed job */
  const char* host = extract_host_from_url(job->url);
  if (host) {
    scheduler_update_host_count(s, host, -1);
  }

  DEBUGP(("[scheduler] Job completed: %s (success: %d)\n", job->url, success));

  /* Call user completion callback if set */
  if (job->on_complete) {
    job->on_complete(job, success, job->user_data);
  }

try_start_new_jobs:
  /* Try to start new jobs now that we have a free slot */
  scheduler_try_start_jobs(s);

  /* Check if we're done */
  if (s->pending_count == 0 && s->active_count == 0) {
    DEBUGP(("[scheduler] All jobs completed. Breaking event loop.\n"));
    evloop_break(s->loop);
  }
}

struct download_job* download_job_new(const char* url, const char* output_path) {
  struct download_job* job = xmalloc(sizeof(struct download_job));

  job->url = xstrdup(url);
  job->output_path = output_path ? xstrdup(output_path) : NULL;
  job->retries_remaining = 3; /* Default retry count */
  job->recursive = false;
  job->timestamping = false;
  job->no_clobber = false;
  job->scheduler = NULL;
  job->retry_timer = NULL;
  job->on_complete = NULL;
  job->user_data = NULL;

  return job;
}

void download_job_free(struct download_job* job) {
  if (!job)
    return;

  /* Stop any pending retry timer */
  if (job->retry_timer) {
    evloop_timer_stop(job->retry_timer);
  }

  free(job->url);
  free(job->output_path);
  free(job);
}

void scheduler_try_start_jobs(struct scheduler* s) {
  while (s->pending_count > 0 && s->active_count < s->max_global) {
    /* Find the next job we can start */
    struct download_job* job = NULL;
    size_t job_index = 0;

    for (size_t i = 0; i < s->pending_count; i++) {
      const char* host = extract_host_from_url(s->pending_jobs[i]->url);
      if (!host)
        continue; /* Skip jobs with invalid URLs */

      int host_count = scheduler_get_host_count(s, host);
      if (host_count < s->max_per_host) {
        job = s->pending_jobs[i];
        job_index = i;
        break;
      }
    }

    if (!job) {
      /* No jobs can be started due to per-host limits */
      break;
    }

    /* Remove job from pending list */
    s->pending_jobs[job_index] = s->pending_jobs[--s->pending_count];

    /* Update host count */
    const char* host = extract_host_from_url(job->url);
    scheduler_update_host_count(s, host, 1);

    /* Increment active count */
    s->active_count++;

    DEBUGP(("[scheduler] Starting job: %s (active: %zu, pending: %zu)\n", job->url, s->active_count, s->pending_count));

    /* In a real implementation, this is where we would start the actual download */
    /* For now, we'll just simulate job completion after a short delay */
    /* This is a placeholder for the actual http-transaction integration */

    /* Simulate job completion after 0.1 seconds */
    struct evloop_timer* completion_timer = evloop_timer_start(s->loop, 0.1, 0.0, (ev_timer_cb_t)scheduler_job_completed, job);

    /* Store timer reference (optional) */
    (void)completion_timer; /* Prevent unused variable warning */
  }
}

int scheduler_get_host_count(struct scheduler* s, const char* host) {
  for (size_t i = 0; i < s->host_counts_size; i++) {
    if (strcmp(s->host_counts[i].host, host) == 0) {
      return s->host_counts[i].count;
    }
  }
  return 0;
}

void scheduler_update_host_count(struct scheduler* s, const char* host, int delta) {
  /* Find existing host entry */
  for (size_t i = 0; i < s->host_counts_size; i++) {
    if (strcmp(s->host_counts[i].host, host) == 0) {
      s->host_counts[i].count += delta;

      /* Remove entry if count reaches zero */
      if (s->host_counts[i].count <= 0) {
        free(s->host_counts[i].host);
        /* Move last element to this position */
        s->host_counts[i] = s->host_counts[--s->host_counts_size];
      }
      return;
    }
  }

  /* Host not found, add new entry if delta is positive */
  if (delta > 0) {
    if (s->host_counts_size >= s->host_counts_capacity) {
      scheduler_grow_host_counts(s);
    }

    s->host_counts[s->host_counts_size].host = xstrdup(host);
    s->host_counts[s->host_counts_size].count = delta;
    s->host_counts_size++;
  }
}

static void scheduler_grow_pending(struct scheduler* s) {
  size_t new_capacity = s->pending_capacity * 2;
  s->pending_jobs = xrealloc(s->pending_jobs, new_capacity * sizeof(struct download_job*));
  s->pending_capacity = new_capacity;
}

static void scheduler_grow_host_counts(struct scheduler* s) {
  size_t new_capacity = s->host_counts_capacity * 2;
  s->host_counts = xrealloc(s->host_counts, new_capacity * sizeof(*s->host_counts));
  s->host_counts_capacity = new_capacity;
}

static const char* extract_host_from_url(const char* url) {
  int dummy;
  struct url* parsed = url_parse(url, &dummy, NULL, false);
  if (!parsed) {
    return NULL;
  }

  const char* host = parsed->host;
  if (!host) {
    url_free(parsed);
    return NULL;
  }

  /* We need to return a string that will persist, so we'll use the host from the parsed URL */
  /* In a real implementation, we might want to cache this or handle it differently */
  static char cached_host[256];
  strncpy(cached_host, host, sizeof(cached_host) - 1);
  cached_host[sizeof(cached_host) - 1] = '\0';

  url_free(parsed);
  return cached_host;
}

static void scheduler_retry_callback(void* arg) {
  struct download_job* job = (struct download_job*)arg;

  /* Clear the retry timer pointer */
  job->retry_timer = NULL;

  if (job->scheduler) {
    DEBUGP(("[scheduler] Retry timer fired, re-adding job: %s\n", job->url));

    /* Re-add the job to the scheduler for retry */
    scheduler_add_job(job->scheduler, job);
  }
  else {
    DEBUGP(("[scheduler] Retry timer fired but no scheduler for job: %s\n", job->url));
    download_job_free(job);
  }
}