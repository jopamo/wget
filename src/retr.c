/* File retrieval.
 * src/retr.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
#include <zlib.h>
#endif

#ifdef HAVE_LIBPROXY
#include "proxy.h"
#endif

#include "exits.h"
#include "utils.h"
#include "retr.h"
#include "progress.h"
#include "url.h"
#include "recur.h"
#include "http.h"
#include "host.h"
#include "connect.h"
#include "convert.h"
#include "scheduler.h"
#include "ptimer.h"
#include "html-url.h"
#include "iri.h"
#include "hsts.h"
#include <ev.h>
#include "evhelpers.h"
#include "evloop.h"
#include "threading.h"

#define FD_READ_LINE_MAX 4096

/* Total size of downloaded files.  Used to enforce quota.  */
wgint total_downloaded_bytes;

/* Total download time in seconds. */
double total_download_time;

/* If non-NULL, the stream to which output should be written.  This
   stream is initialized when `-O' is used.  */
FILE* output_stream;

/* Whether output_document is a regular file we can manipulate,
   i.e. not `-' or a device file. */
bool output_stream_regular;

struct bandwidth_limiter {
  wgint chunk_bytes;
  double chunk_start;
  double sleep_adjust;
};

enum bandwidth_plan { BANDWIDTH_PLAN_NONE = 0, BANDWIDTH_PLAN_SLEEP, BANDWIDTH_PLAN_DEFER };

static void bandwidth_limiter_reset(struct bandwidth_limiter* limiter) {
  if (!limiter)
    return;
  memset(limiter, 0, sizeof(*limiter));
}

static void bandwidth_limiter_reset_window(struct bandwidth_limiter* limiter, struct ptimer* timer) {
  if (!limiter || !timer)
    return;
  limiter->chunk_bytes = 0;
  limiter->chunk_start = ptimer_read(timer);
}

static enum bandwidth_plan bandwidth_limiter_plan(struct bandwidth_limiter* limiter, wgint bytes, struct ptimer* timer, double* sleep_time) {
  double delta_t, expected;

  if (!limiter || !timer)
    return BANDWIDTH_PLAN_NONE;

  if (limiter->chunk_start == 0)
    limiter->chunk_start = ptimer_read(timer);

  limiter->chunk_bytes += bytes;
  delta_t = ptimer_read(timer) - limiter->chunk_start;
  expected = (double)limiter->chunk_bytes / opt.limit_rate;

  if (expected > delta_t) {
    double slp = expected - delta_t + limiter->sleep_adjust;
    if (slp < 0.2) {
      DEBUGP(("deferring a %.2f ms sleep (%s/%.2f).\n", slp * 1000, number_to_static_string(limiter->chunk_bytes), delta_t));
      return BANDWIDTH_PLAN_DEFER;
    }
    if (sleep_time)
      *sleep_time = slp;
    return BANDWIDTH_PLAN_SLEEP;
  }

  bandwidth_limiter_reset_window(limiter, timer);
  return BANDWIDTH_PLAN_NONE;
}

static void bandwidth_limiter_commit(struct bandwidth_limiter* limiter, struct ptimer* timer, double requested_sleep, double actual_sleep) {
  if (!limiter || !timer)
    return;

  bandwidth_limiter_reset_window(limiter, timer);
  limiter->sleep_adjust = requested_sleep - actual_sleep;
  if (limiter->sleep_adjust > 0.5)
    limiter->sleep_adjust = 0.5;
  else if (limiter->sleep_adjust < -0.5)
    limiter->sleep_adjust = -0.5;
}

#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
static voidpf zalloc(voidpf opaque, unsigned int items, unsigned int size) {
  (void)opaque;
  return (voidpf)xcalloc(items, size);
}

static void zfree(voidpf opaque, voidpf address) {
  (void)opaque;
  xfree(address);
}

#endif

/* Limit the bandwidth by pausing the download for an amount of time.
   BYTES is the number of bytes received from the network, and TIMER
   is the timer that started at the beginning of download.  */

/* Write data in BUF to OUT.  However, if *SKIP is non-zero, skip that
   amount of data and decrease SKIP.  Increment *TOTAL by the amount
   of data written.  If OUT2 is not NULL, also write BUF to OUT2.
   In case of error writing to OUT, -2 is returned.  In case of error
   writing to OUT2, -3 is returned.  Return 1 if the whole BUF was
   skipped.  */

static int write_data(FILE* out, FILE* out2, const char* buf, int bufsize, wgint* skip, wgint* written) {
  if (out == NULL && out2 == NULL)
    return 1;

  if (skip) {
    if (*skip > bufsize) {
      *skip -= bufsize;
      return 1;
    }
    if (*skip) {
      buf += *skip;
      bufsize -= *skip;
      *skip = 0;
      if (bufsize == 0)
        return 1;
    }
  }

  if (out)
    fwrite(buf, 1, bufsize, out);
  if (out2)
    fwrite(buf, 1, bufsize, out2);

  if (written)
    *written += bufsize;

  /* Immediately flush the downloaded data.  This should not hinder
     performance: fast downloads will arrive in large 16K chunks
     (which stdio would write out immediately anyway), and slow
     downloads wouldn't be limited by disk speed.  */

  if (out)
    fflush(out);
  if (out2)
    fflush(out2);

  if (out && ferror(out))
    return -2;
  else if (out2 && ferror(out2))
    return -3;

  return 0;
}

/* Read the contents of file descriptor FD until it the connection
   terminates or a read error occurs.  The data is read in portions of
   up to 16K and written to OUT as it arrives.  If opt.verbose is set,
   the progress is shown.

   TOREAD is the amount of data expected to arrive, normally only used
   by the progress gauge.

   STARTPOS is the position from which the download starts, used by
   the progress gauge.  If QTYREAD is non-NULL, the value it points to
   is incremented by the amount of data read from the network.  If
   QTYWRITTEN is non-NULL, the value it points to is incremented by
   the amount of data written to disk.  The time it took to download
   the data is stored to ELAPSED.

   If OUT2 is non-NULL, the contents is also written to OUT2.
   OUT2 will get an exact copy of the response: if this is a chunked
   response, everything -- including the chunk headers -- is written
   to OUT2.  (OUT will only get the unchunked response.)

   The function exits and returns the amount of data read.  In case of
   error while reading data, -1 is returned.  In case of error while
   writing data to OUT, -2 is returned.  In case of error while writing
   data to OUT2, -3 is returned.  */

/* Asynchronous wrapper for fd_read_body(), driven by libev watchers.
   This is a transitional helper so higher level code can attach
   per-transfer state to the central event loop without changing the
   existing blocking body reader yet.  */

typedef void (*retr_body_done_cb)(int status, wgint qtyread, wgint qtywritten, double elapsed, void* user_data);

enum retr_chunk_state { RETR_CHUNK_STATE_NONE = 0, RETR_CHUNK_STATE_HEADER, RETR_CHUNK_STATE_DATA, RETR_CHUNK_STATE_DATA_CRLF, RETR_CHUNK_STATE_FINAL_CRLF, RETR_CHUNK_STATE_DONE };

struct retr_async_ctx {
  struct ev_loop* loop;
  const char* downloaded_filename;
  int fd;
  FILE* out;
  wgint toread;
  wgint startpos;
  wgint* qtyread;
  wgint* qtywritten;
  double* elapsed;
  int flags;
  FILE* out2;

  retr_body_done_cb done_cb;
  void* user_data;

  ev_io io_watcher;
  ev_timer timeout_watcher;
  bool timeout_active;
  ev_timer throttle_watcher;
  bool throttle_active;
  ev_timer progress_watcher;
  bool progress_active;

  bool exact;
  bool chunked;
  bool finished;
  int result;
  int error_no;
  bool cpu_paused;
  bool cpu_job_pending;

  wgint sum_read;
  wgint sum_written;
  wgint skip;

  struct bandwidth_limiter limiter;
  double throttle_delay;
  double throttle_start;

  struct ptimer* timer;
  double last_successful_read_tm;

  void* progress;
  bool progress_interactive;

  char* dlbuf;
  size_t dlbufsize;

#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  bool gzip_mode;
  z_stream gzstream;
  char* gzbuf;
  unsigned int gzbufsize;
#endif

  struct {
    enum retr_chunk_state phase;
    wgint remaining;
    char line[FD_READ_LINE_MAX + 1];
    size_t line_len;
  } chunk;

  bool loop_ref;
};

static void retr_async_stop_watchers(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop)
    return;
  if (ev_is_active(&ctx->io_watcher))
    ev_io_stop(ctx->loop, &ctx->io_watcher);
  if (ctx->timeout_active) {
    ev_timer_stop(ctx->loop, &ctx->timeout_watcher);
    ctx->timeout_active = false;
  }
  if (ctx->throttle_active) {
    ev_timer_stop(ctx->loop, &ctx->throttle_watcher);
    ctx->throttle_active = false;
  }
  if (ctx->progress_active) {
    ev_timer_stop(ctx->loop, &ctx->progress_watcher);
    ctx->progress_active = false;
  }
}

static void retr_async_finish(struct retr_async_ctx* ctx, int status);
static void retr_async_fail(struct retr_async_ctx* ctx, int status);
static void retr_async_maybe_throttle(struct retr_async_ctx* ctx, wgint bytes);

static void retr_async_reset_timeout(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->timeout_active)
    return;
  ev_timer_stop(ctx->loop, &ctx->timeout_watcher);
  ctx->timeout_active = false;
}

static void retr_async_arm_timeout(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop || opt.read_timeout <= 0)
    return;
  ev_timer_set(&ctx->timeout_watcher, opt.read_timeout, 0);
  ctx->timeout_active = true;
  ev_timer_start(ctx->loop, &ctx->timeout_watcher);
}

static void retr_async_start_progress_timer(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop || !ctx->progress_interactive)
    return;
  ev_timer_set(&ctx->progress_watcher, 0.95, 0.95);
  ctx->progress_active = true;
  ev_timer_start(ctx->loop, &ctx->progress_watcher);
}

static void retr_async_pause_io(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop || ctx->finished || ctx->cpu_paused)
    return;
  if (ev_is_active(&ctx->io_watcher))
    ev_io_stop(ctx->loop, &ctx->io_watcher);
  retr_async_reset_timeout(ctx);
  ctx->cpu_paused = true;
}

static void retr_async_resume_io(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop || ctx->finished || !ctx->cpu_paused)
    return;
  ctx->cpu_paused = false;
  if (ctx->throttle_active)
    return;
  if (!ev_is_active(&ctx->io_watcher))
    ev_io_start(ctx->loop, &ctx->io_watcher);
  retr_async_arm_timeout(ctx);
}

#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
struct retr_async_gzip_job {
  struct retr_async_ctx* ctx;
  char* data;
  size_t len;
  wgint bytes_read;
  int status;
  int error_no;
};

static int retr_async_process_gzip_chunk(struct retr_async_ctx* ctx, const char* buf, size_t len, int* error_no) {
  int write_res;

  if (ctx->out2) {
    write_res = write_data(NULL, ctx->out2, buf, len, NULL, NULL);
    if (write_res < 0) {
      if (error_no)
        *error_no = errno;
      return write_res;
    }
  }

  ctx->gzstream.avail_in = len;
  ctx->gzstream.next_in = (unsigned char*)buf;

  do {
    ctx->gzstream.avail_out = ctx->gzbufsize;
    ctx->gzstream.next_out = (unsigned char*)ctx->gzbuf;
    int err = inflate(&ctx->gzstream, Z_NO_FLUSH);
    if (err == Z_MEM_ERROR) {
      if (error_no)
        *error_no = ENOMEM;
      return -1;
    }
    if (err == Z_NEED_DICT || err == Z_DATA_ERROR) {
      if (error_no)
        *error_no = EINVAL;
      return -1;
    }
    unsigned int produced = ctx->gzbufsize - ctx->gzstream.avail_out;
    if (produced > 0) {
      write_res = write_data(ctx->out, NULL, ctx->gzbuf, produced, &ctx->skip, &ctx->sum_written);
      if (write_res < 0) {
        if (error_no)
          *error_no = errno;
        return write_res;
      }
    }
    if (err == Z_STREAM_END)
      break;
  } while (ctx->gzstream.avail_out == 0);

  return 0;
}

static void retr_async_gzip_job_work(void* arg) {
  struct retr_async_gzip_job* job = arg;
  int err_no = 0;
  job->status = retr_async_process_gzip_chunk(job->ctx, job->data, job->len, &err_no);
  job->error_no = err_no;
  xfree(job->data);
  job->data = NULL;
}

static void retr_async_gzip_job_complete(void* arg) {
  struct retr_async_gzip_job* job = arg;
  struct retr_async_ctx* ctx = job->ctx;

  ctx->cpu_job_pending = false;

  if (job->status < 0) {
    ctx->error_no = job->error_no;
    ctx->result = job->status;
    retr_async_fail(ctx, ctx->result ? ctx->result : -1);
    xfree(job);
    return;
  }

  ctx->sum_read += job->bytes_read;
  if (ctx->timer)
    ptimer_measure(ctx->timer);
  if (ctx->progress)
    progress_update(ctx->progress, job->bytes_read, ctx->timer ? ptimer_read(ctx->timer) : 0);
  retr_async_maybe_throttle(ctx, job->bytes_read);

  if (ctx->exact && ctx->sum_read >= ctx->toread && !ctx->chunked)
    retr_async_finish(ctx, ctx->result);
  else
    retr_async_resume_io(ctx);

  xfree(job);
}

static bool retr_async_dispatch_gzip(struct retr_async_ctx* ctx, const char* buf, size_t len) {
  if (!wget_worker_pool_available()) {
    int err_no = 0;
    int status = retr_async_process_gzip_chunk(ctx, buf, len, &err_no);
    if (status < 0) {
      ctx->error_no = err_no;
      ctx->result = status;
      return false;
    }
    return true;
  }

  struct retr_async_gzip_job* job = xcalloc(1, sizeof(*job));
  job->ctx = ctx;
  job->len = len;
  job->bytes_read = len;
  job->data = xmemdup(buf, len);
  if (!job->data) {
    xfree(job);
    ctx->error_no = ENOMEM;
    ctx->result = -1;
    return false;
  }

  if (!wget_worker_pool_submit(retr_async_gzip_job_work, retr_async_gzip_job_complete, job)) {
    int err_no = 0;
    int status;
    xfree(job->data);
    xfree(job);
    status = retr_async_process_gzip_chunk(ctx, buf, len, &err_no);
    if (status < 0) {
      ctx->error_no = err_no;
      ctx->result = status;
      return false;
    }
    return true;
  }

  retr_async_pause_io(ctx);
  ctx->cpu_job_pending = true;
  return true;
}
#endif

static void retr_async_destroy_buffers(struct retr_async_ctx* ctx) {
  if (!ctx)
    return;
  xfree(ctx->dlbuf);
  ctx->dlbuf = NULL;
#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  if (ctx->gzbuf) {
    xfree(ctx->gzbuf);
    ctx->gzbuf = NULL;
  }
  if (ctx->gzip_mode)
    inflateEnd(&ctx->gzstream);
#endif
  if (ctx->timer) {
    ptimer_destroy(ctx->timer);
    ctx->timer = NULL;
  }
}

static void retr_async_finish(struct retr_async_ctx* ctx, int status) {
  double elapsed = 0;
  if (!ctx || ctx->finished)
    return;

  ctx->finished = true;
  retr_async_stop_watchers(ctx);

  if (ctx->progress)
    progress_finish(ctx->progress, ctx->timer ? ptimer_read(ctx->timer) : 0);

  if (ctx->timer)
    elapsed = ptimer_read(ctx->timer);

  if (ctx->elapsed)
    *ctx->elapsed += elapsed;

  if (ctx->qtyread)
    *ctx->qtyread += ctx->sum_read;
  if (ctx->qtywritten)
    *ctx->qtywritten += ctx->sum_written;

  retr_async_destroy_buffers(ctx);

  if (ctx->loop_ref) {
    wget_ev_loop_transfer_unref();
    ctx->loop_ref = false;
  }

  errno = ctx->error_no;

  if (ctx->done_cb)
    ctx->done_cb(status, ctx->sum_read, ctx->sum_written, elapsed, ctx->user_data);

  xfree(ctx);
}

static void retr_async_fail(struct retr_async_ctx* ctx, int status) {
  if (!ctx)
    return;
  ctx->result = status;
  retr_async_finish(ctx, status);
}

static size_t retr_async_planned_read_size(struct retr_async_ctx* ctx) {
  if (!ctx)
    return 0;
  if (ctx->chunked)
    return ctx->dlbufsize;
  if (ctx->exact) {
    wgint remaining = ctx->toread - ctx->sum_read;
    if (remaining <= 0)
      return 0;
    if ((wgint)ctx->dlbufsize < remaining)
      return ctx->dlbufsize;
    return remaining;
  }
  return ctx->dlbufsize;
}

static void retr_async_maybe_throttle(struct retr_async_ctx* ctx, wgint bytes) {
  double delay = 0;
  enum bandwidth_plan plan;

  if (!ctx || !opt.limit_rate || !ctx->timer)
    return;

  plan = bandwidth_limiter_plan(&ctx->limiter, bytes, ctx->timer, &delay);
  if (plan != BANDWIDTH_PLAN_SLEEP)
    return;

  ctx->throttle_delay = delay;
  ctx->throttle_start = ctx->timer ? ptimer_read(ctx->timer) : 0;
  ctx->throttle_active = true;
  retr_async_reset_timeout(ctx);
  ev_timer_set(&ctx->throttle_watcher, delay, 0);
  ev_timer_start(ctx->loop, &ctx->throttle_watcher);
  if (ev_is_active(&ctx->io_watcher))
    ev_io_stop(ctx->loop, &ctx->io_watcher);
}

static bool retr_async_write_payload(struct retr_async_ctx* ctx, const char* buf, size_t len);
static bool retr_async_process_buffer(struct retr_async_ctx* ctx, const char* buf, size_t len);

static void retr_async_timeout_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct retr_async_ctx* ctx = w->data;
  ctx->timeout_active = false;
  ctx->error_no = ETIMEDOUT;
  retr_async_fail(ctx, -1);
}

static void retr_async_throttle_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct retr_async_ctx* ctx = w->data;
  double now = ctx->timer ? ptimer_read(ctx->timer) : ctx->throttle_start + ctx->throttle_delay;
  double actual = now - ctx->throttle_start;

  ctx->throttle_active = false;
  bandwidth_limiter_commit(&ctx->limiter, ctx->timer, ctx->throttle_delay, actual);
  if (!ctx->cpu_paused) {
    if (!ev_is_active(&ctx->io_watcher))
      ev_io_start(ctx->loop, &ctx->io_watcher);
    retr_async_arm_timeout(ctx);
  }
}

static void retr_async_progress_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct retr_async_ctx* ctx = w->data;
  if (!ctx->progress || !ctx->timer)
    return;
  ptimer_measure(ctx->timer);
  progress_update(ctx->progress, 0, ptimer_read(ctx->timer));
}

static void retr_async_io_cb(EV_P_ ev_io* w, int revents) {
  struct retr_async_ctx* ctx = w->data;
  size_t rdsize;
  int ret;

  if (!ctx || !(revents & EV_READ) || ctx->finished)
    return;

  retr_async_reset_timeout(ctx);
  retr_async_arm_timeout(ctx);

  rdsize = retr_async_planned_read_size(ctx);
  if (rdsize == 0 && !ctx->chunked) {
    retr_async_finish(ctx, ctx->result);
    return;
  }

  ret = fd_read(ctx->fd, ctx->dlbuf, rdsize ? rdsize : ctx->dlbufsize, 0);
  if (ret < 0) {
    ctx->error_no = errno;
    retr_async_fail(ctx, -1);
    return;
  }
  if (ret == 0) {
    if (ctx->chunked && ctx->chunk.phase != RETR_CHUNK_STATE_DONE) {
      ctx->error_no = 0;
      retr_async_fail(ctx, -1);
      return;
    }
    retr_async_finish(ctx, ctx->result);
    return;
  }

  if (ctx->timer)
    ptimer_measure(ctx->timer);

  if (!retr_async_process_buffer(ctx, ctx->dlbuf, ret))
    retr_async_fail(ctx, ctx->result ? ctx->result : -1);
}

static bool retr_async_chunk_handle_line(struct retr_async_ctx* ctx) {
  wgint size;

  if (!ctx)
    return false;

  if (ctx->out2 && ctx->chunk.line_len)
    fwrite(ctx->chunk.line, 1, ctx->chunk.line_len, ctx->out2);

  switch (ctx->chunk.phase) {
    case RETR_CHUNK_STATE_HEADER:
      size = strtol(ctx->chunk.line, NULL, 16);
      if (size < 0) {
        ctx->error_no = EINVAL;
        return false;
      }
      ctx->chunk.remaining = size;
      ctx->chunk.phase = (size == 0) ? RETR_CHUNK_STATE_FINAL_CRLF : RETR_CHUNK_STATE_DATA;
      break;
    case RETR_CHUNK_STATE_DATA_CRLF:
      ctx->chunk.phase = RETR_CHUNK_STATE_HEADER;
      break;
    case RETR_CHUNK_STATE_FINAL_CRLF:
      ctx->chunk.phase = RETR_CHUNK_STATE_DONE;
      retr_async_finish(ctx, ctx->result);
      break;
    default:
      break;
  }
  return true;
}

static bool retr_async_chunk_consume_line(struct retr_async_ctx* ctx, const char* buf, size_t len, size_t* consumed) {
  size_t used = 0;
  if (consumed)
    *consumed = 0;

  while (used < len) {
    if (ctx->chunk.line_len >= FD_READ_LINE_MAX) {
      ctx->error_no = ENOMEM;
      return false;
    }
    ctx->chunk.line[ctx->chunk.line_len++] = buf[used++];
    if (ctx->chunk.line[ctx->chunk.line_len - 1] == '\n') {
      ctx->chunk.line[ctx->chunk.line_len] = '\0';
      if (!retr_async_chunk_handle_line(ctx))
        return false;
      ctx->chunk.line_len = 0;
      break;
    }
  }
  if (consumed)
    *consumed = used;
  return true;
}

static bool retr_async_process_buffer(struct retr_async_ctx* ctx, const char* buf, size_t len) {
  size_t offset = 0;

  while (offset < len && !ctx->finished) {
    if (ctx->chunked) {
      switch (ctx->chunk.phase) {
        case RETR_CHUNK_STATE_HEADER:
        case RETR_CHUNK_STATE_DATA_CRLF:
        case RETR_CHUNK_STATE_FINAL_CRLF: {
          size_t consumed = 0;
          if (!retr_async_chunk_consume_line(ctx, buf + offset, len - offset, &consumed))
            return false;
          offset += consumed;
          break;
        }
        case RETR_CHUNK_STATE_DATA: {
          wgint remaining = ctx->chunk.remaining;
          size_t tocopy = MIN((size_t)remaining, len - offset);
          if (!retr_async_write_payload(ctx, buf + offset, tocopy))
            return false;
          ctx->chunk.remaining -= tocopy;
          offset += tocopy;
          if (ctx->chunk.remaining == 0)
            ctx->chunk.phase = RETR_CHUNK_STATE_DATA_CRLF;
          break;
        }
        case RETR_CHUNK_STATE_DONE:
          retr_async_finish(ctx, ctx->result);
          return true;
        default:
          break;
      }
    }
    else {
      size_t tocopy = len - offset;
      if (ctx->exact) {
        wgint remaining = ctx->toread - ctx->sum_read;
        if (remaining <= 0) {
          retr_async_finish(ctx, ctx->result);
          return true;
        }
        if (tocopy > (size_t)remaining)
          tocopy = remaining;
      }
      if (!retr_async_write_payload(ctx, buf + offset, tocopy))
        return false;
      offset += tocopy;
    }
  }
  return true;
}

static bool retr_async_write_payload(struct retr_async_ctx* ctx, const char* buf, size_t len) {
  int write_res;
  if (!len)
    return true;

#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  if (ctx->gzip_mode) {
    if (!retr_async_dispatch_gzip(ctx, buf, len))
      return false;
    if (ctx->cpu_job_pending)
      return true;
  }
  else
#endif
  {
    write_res = write_data(ctx->out, ctx->out2, buf, len, &ctx->skip, &ctx->sum_written);
    if (write_res < 0) {
      ctx->error_no = errno;
      ctx->result = write_res;
      return false;
    }
  }

  ctx->sum_read += len;
  if (ctx->progress)
    progress_update(ctx->progress, len, ctx->timer ? ptimer_read(ctx->timer) : 0);
  retr_async_maybe_throttle(ctx, len);

  if (ctx->exact && ctx->sum_read >= ctx->toread && !ctx->chunked)
    retr_async_finish(ctx, ctx->result);

  return true;
}

static void retr_async_init_watcher(ev_io* watcher, struct retr_async_ctx* ctx) {
  ev_io_init(watcher, retr_async_io_cb, ctx->fd, EV_READ);
  watcher->data = ctx;
}

static void retr_async_init_timers(struct retr_async_ctx* ctx) {
  ev_timer_init(&ctx->timeout_watcher, retr_async_timeout_cb, 0, 0);
  ctx->timeout_watcher.data = ctx;
  ev_timer_init(&ctx->throttle_watcher, retr_async_throttle_cb, 0, 0);
  ctx->throttle_watcher.data = ctx;
  ev_timer_init(&ctx->progress_watcher, retr_async_progress_cb, 0, 0);
  ctx->progress_watcher.data = ctx;
}

static struct retr_async_ctx* retr_async_ctx_create(struct ev_loop* loop,
                                                    const char* downloaded_filename,
                                                    int fd,
                                                    FILE* out,
                                                    wgint toread,
                                                    wgint startpos,
                                                    wgint* qtyread,
                                                    wgint* qtywritten,
                                                    double* elapsed,
                                                    int flags,
                                                    FILE* out2,
                                                    retr_body_done_cb done_cb,
                                                    void* user_data) {
  struct retr_async_ctx* ctx = xcalloc(1, sizeof(*ctx));
  ctx->loop = loop;
  ctx->downloaded_filename = downloaded_filename;
  ctx->fd = fd;
  ctx->out = out;
  ctx->toread = toread;
  ctx->startpos = startpos;
  ctx->qtyread = qtyread;
  ctx->qtywritten = qtywritten;
  ctx->elapsed = elapsed;
  ctx->flags = flags;
  ctx->out2 = out2;
  ctx->done_cb = done_cb;
  ctx->user_data = user_data;
  ctx->exact = !!(flags & rb_read_exactly);
  ctx->chunked = (flags & rb_chunked_transfer_encoding) != 0;
  ctx->skip = (flags & rb_skip_startpos) ? startpos : 0;
  ctx->result = 0;
  ctx->error_no = 0;
  ctx->dlbufsize = MAX(BUFSIZ, 64 * 1024);
  ctx->dlbuf = xmalloc(ctx->dlbufsize);
  ctx->chunk.phase = ctx->chunked ? RETR_CHUNK_STATE_HEADER : RETR_CHUNK_STATE_NONE;

#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  if (flags & rb_compressed_gzip) {
    ctx->gzip_mode = true;
    ctx->gzbufsize = ctx->dlbufsize * 4;
    ctx->gzbuf = xmalloc(ctx->gzbufsize);
    ctx->gzstream.zalloc = zalloc;
    ctx->gzstream.zfree = zfree;
    ctx->gzstream.opaque = Z_NULL;
    ctx->gzstream.next_in = Z_NULL;
    ctx->gzstream.avail_in = 0;
    if (inflateInit2(&ctx->gzstream, 32 | 15) != Z_OK) {
      ctx->error_no = EINVAL;
      retr_async_destroy_buffers(ctx);
      xfree(ctx);
      return NULL;
    }
  }
#endif

  if (opt.show_progress) {
    const char* filename_progress;
    wgint start = ctx->skip ? 0 : startpos;
    if (opt.dir_prefix)
      filename_progress = downloaded_filename + strlen(opt.dir_prefix) + 1;
    else
      filename_progress = downloaded_filename;
    ctx->progress = progress_create(filename_progress, start, start + toread);
    ctx->progress_interactive = progress_interactive_p(ctx->progress);
  }

  if (ctx->progress || opt.limit_rate || elapsed) {
    ctx->timer = ptimer_new();
    ctx->last_successful_read_tm = 0;
  }

  if (opt.limit_rate && (size_t)opt.limit_rate < ctx->dlbufsize)
    ctx->dlbufsize = opt.limit_rate;

  bandwidth_limiter_reset(&ctx->limiter);
  retr_async_init_watcher(&ctx->io_watcher, ctx);
  retr_async_init_timers(ctx);
  ctx->io_watcher.data = ctx;

  return ctx;
}

static void retr_async_ctx_start(struct retr_async_ctx* ctx) {
  if (!ctx || !ctx->loop)
    return;
  ev_io_start(ctx->loop, &ctx->io_watcher);
  ctx->io_watcher.data = ctx;
  ctx->timeout_watcher.data = ctx;
  ctx->throttle_watcher.data = ctx;
  ctx->progress_watcher.data = ctx;
  if (opt.read_timeout > 0)
    retr_async_arm_timeout(ctx);
  if (ctx->progress_interactive)
    retr_async_start_progress_timer(ctx);
  ctx->loop_ref = true;
  wget_ev_loop_transfer_ref();
}

int retr_body_start_async(struct ev_loop* loop,
                          const char* downloaded_filename,
                          int fd,
                          FILE* out,
                          wgint toread,
                          wgint startpos,
                          wgint* qtyread,
                          wgint* qtywritten,
                          double* elapsed,
                          int flags,
                          FILE* out2,
                          retr_body_done_cb done_cb,
                          void* user_data) {
  struct retr_async_ctx* ctx = retr_async_ctx_create(loop, downloaded_filename, fd, out, toread, startpos, qtyread, qtywritten, elapsed, flags, out2, done_cb, user_data);
  if (!ctx)
    return -1;

  retr_async_ctx_start(ctx);
  return 0;
}

/* Read a hunk of data from FD, up until a terminator.  The hunk is
   limited by whatever the TERMINATOR callback chooses as its
   terminator.  For example, if terminator stops at newline, the hunk
   will consist of a line of data; if terminator stops at two
   newlines, it can be used to read the head of an HTTP response.
   Upon determining the boundary, the function returns the data (up to
   the terminator) in malloc-allocated storage.

   In case of read error, NULL is returned.  In case of EOF and no
   data read, NULL is returned and errno set to 0.  In case of having
   read some data, but encountering EOF before seeing the terminator,
   the data that has been read is returned, but it will (obviously)
   not contain the terminator.

   The TERMINATOR function is called with three arguments: the
   beginning of the data read so far, the beginning of the current
   block of peeked-at data, and the length of the current block.
   Depending on its needs, the function is free to choose whether to
   analyze all data or just the newly arrived data.  If TERMINATOR
   returns NULL, it means that the terminator has not been seen.
   Otherwise it should return a pointer to the charactre immediately
   following the terminator.

   The idea is to be able to read a line of input, or otherwise a hunk
   of text, such as the head of an HTTP request, without crossing the
   boundary, so that the next call to fd_read etc. reads the data
   after the hunk.  To achieve that, this function does the following:

   1. Peek at incoming data.

   2. Determine whether the peeked data, along with the previously
      read data, includes the terminator.

      2a. If yes, read the data until the end of the terminator, and
          exit.

      2b. If no, read the peeked data and goto 1.

   The function is careful to assume as little as possible about the
   implementation of peeking.  For example, every peek is followed by
   a read.  If the read returns a different amount of data, the
   process is retried until all data arrives safely.

   SIZEHINT is the buffer size sufficient to hold all the data in the
   typical case (it is used as the initial buffer size).  MAXSIZE is
   the maximum amount of memory this function is allowed to allocate,
   or 0 if no upper limit is to be enforced.

   This function should be used as a building block for other
   functions -- see fd_read_line as a simple example.  */

char* fd_read_hunk(int fd, hunk_terminator_t terminator, long sizehint, long maxsize) {
  long bufsize = sizehint;
  char* hunk = xmalloc(bufsize);
  int tail = 0; /* tail position in HUNK */

  assert(!maxsize || maxsize >= bufsize);

  while (1) {
    const char* end;
    int pklen, rdlen, remain;

    /* First, peek at the available data. */

    pklen = fd_peek(fd, hunk + tail, bufsize - 1 - tail, -1);
    if (pklen < 0) {
      xfree(hunk);
      return NULL;
    }
    end = terminator(hunk, hunk + tail, pklen);
    if (end) {
      /* The data contains the terminator: we'll drain the data up
         to the end of the terminator.  */
      remain = end - (hunk + tail);
      assert(remain >= 0);
      if (remain == 0) {
        /* No more data needs to be read. */
        hunk[tail] = '\0';
        return hunk;
      }
      if (bufsize - 1 < tail + remain) {
        bufsize = tail + remain + 1;
        hunk = xrealloc(hunk, bufsize);
      }
    }
    else
      /* No terminator: simply read the data we know is (or should
         be) available.  */
      remain = pklen;

    /* Now, read the data.  Note that we make no assumptions about
       how much data we'll get.  (Some TCP stacks are notorious for
       read returning less data than the previous MSG_PEEK.)  */

    rdlen = fd_read(fd, hunk + tail, remain, 0);
    if (rdlen < 0) {
      xfree(hunk);
      return NULL;
    }
    tail += rdlen;
    hunk[tail] = '\0';

    if (rdlen == 0) {
      if (tail == 0) {
        /* EOF without anything having been read */
        xfree(hunk);
        errno = 0;
        return NULL;
      }
      else
        /* EOF seen: return the data we've read. */
        return hunk;
    }
    if (end && rdlen == remain)
      /* The terminator was seen and the remaining data drained --
         we got what we came for.  */
      return hunk;

    /* Keep looping until all the data arrives. */

    if (tail == bufsize - 1) {
      /* Double the buffer size, but refuse to allocate more than
         MAXSIZE bytes.  */
      if (maxsize && bufsize >= maxsize) {
        xfree(hunk);
        errno = ENOMEM;
        return NULL;
      }
      bufsize <<= 1;
      if (maxsize && bufsize > maxsize)
        bufsize = maxsize;
      hunk = xrealloc(hunk, bufsize);
    }
  }
}

static const char* line_terminator(const char* start WGET_ATTR_UNUSED, const char* peeked, int peeklen) {
  const char* p = memchr(peeked, '\n', peeklen);
  if (p)
    /* p+1 because the line must include '\n' */
    return p + 1;
  return NULL;
}

/* The maximum size of the single line we agree to accept.  This is
   not meant to impose an arbitrary limit, but to protect the user
   from Wget slurping up available memory upon encountering malicious
   or buggy server output.  Define it to 0 to remove the limit.  */
/* Read one line from FD and return it.  The line is allocated using
   malloc, but is never larger than FD_READ_LINE_MAX.

   If an error occurs, or if no data can be read, NULL is returned.
   In the former case errno indicates the error condition, and in the
   latter case, errno is NULL.  */

char* fd_read_line(int fd) {
  return fd_read_hunk(fd, line_terminator, 128, FD_READ_LINE_MAX);
}

/* Return a printed representation of the download rate, along with
   the units appropriate for the download speed.  */

const char* retr_rate(wgint bytes, double secs) {
  static char res[20];
  static const char* rate_names[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
  static const char* rate_names_bits[] = {"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"};
  int units;

  double dlrate = calc_rate(bytes, secs, &units);
  /* Use more digits for smaller numbers (regardless of unit used),
     e.g. "1022", "247", "12.5", "2.38".  */
  snprintf(res, sizeof(res), "%.*f %s", dlrate >= 99.95 ? 0 : dlrate >= 9.995 ? 1 : 2, dlrate, !opt.report_bps ? rate_names[units] : rate_names_bits[units]);

  return res;
}

/* Calculate the download rate and trim it as appropriate for the
   speed.  Appropriate means that if rate is greater than 1K/s,
   kilobytes are used, and if rate is greater than 1MB/s, megabytes
   are used.

   UNITS is zero for B/s, one for KB/s, two for MB/s, and three for
   GB/s.  */

double calc_rate(wgint bytes, double secs, int* units) {
  double dlrate;
  double bibyte;

  if (!opt.report_bps)
    bibyte = 1024.0;
  else
    bibyte = 1000.0;

  if (secs == 0)
    /* If elapsed time is exactly zero, it means we're under the
       resolution of the timer.  This can easily happen on systems
       that use time() for the timer.  Since the interval lies between
       0 and the timer's resolution, assume half the resolution.  */
    secs = ptimer_resolution() / 2.0;

  dlrate = secs ? convert_to_bits(bytes) / secs : 0;
  if (dlrate < bibyte)
    *units = 0;
  else if (dlrate < (bibyte * bibyte))
    *units = 1, dlrate /= bibyte;
  else if (dlrate < (bibyte * bibyte * bibyte))
    *units = 2, dlrate /= (bibyte * bibyte);
  else if (dlrate < (bibyte * bibyte * bibyte * bibyte))
    *units = 3, dlrate /= (bibyte * bibyte * bibyte);
  else {
    *units = 4, dlrate /= (bibyte * bibyte * bibyte * bibyte);
    if (dlrate > 99.99)
      dlrate = 99.99; /* upper limit 99.99TB/s */
  }

  return dlrate;
}

#define SUSPEND_METHOD                    \
  do {                                    \
    method_suspended = true;              \
    saved_body_data = opt.body_data;      \
    saved_body_file_name = opt.body_file; \
    saved_method = opt.method;            \
    opt.body_data = NULL;                 \
    opt.body_file = NULL;                 \
    opt.method = NULL;                    \
  } while (0)

#define RESTORE_METHOD                      \
  do {                                      \
    if (method_suspended) {                 \
      opt.body_data = saved_body_data;      \
      opt.body_file = saved_body_file_name; \
      opt.method = saved_method;            \
      method_suspended = false;             \
    }                                       \
  } while (0)

static char* getproxy(struct url*);

/* Retrieve the given URL.  Decides which loop to call -- HTTP, FTP,
   FTP, proxy, etc.  */

/* #### This function should be rewritten so it doesn't return from
   multiple points. */

static void retrieve_url_http_loop_cb(struct http_transaction_ctx* http_ctx, uerr_t status);
static struct retrieve_url_ctx* g_current_ctx = NULL;
static uerr_t g_async_result = -1;
static bool g_finished = false;

static void blocking_final_cb_for_retrieve_url(struct retrieve_url_ctx* ctx) {
  g_async_result = ctx->result;
  g_finished = true;
}

static void retrieve_url_http_loop_cb(struct http_transaction_ctx* http_ctx, uerr_t status) {
  struct retrieve_url_ctx* ctx = (struct retrieve_url_ctx*)http_ctx->tctx->user_data;
  assert(ctx != NULL);

  (void)status;

  // Transfer results from http_ctx to retrieve_url_ctx
  if (http_ctx->newloc && *http_ctx->newloc) {
    if (*ctx->newloc)
      xfree(*ctx->newloc);
    *ctx->newloc = xstrdup(*http_ctx->newloc);
  }
  if (http_ctx->local_file && *http_ctx->local_file) {
    if (*ctx->local_file)
      xfree(*ctx->local_file);
    *ctx->local_file = xstrdup(*http_ctx->local_file);
  }
  if (ctx->dt && http_ctx->dt)
    *ctx->dt = *http_ctx->dt;
  ctx->result = http_ctx->retval;

  // Cleanup http_ctx as it's no longer needed
  http_loop_cleanup(http_ctx);

  // Continue the retrieve_url state machine
  retrieve_url_continue_async(ctx, ctx->result);
}

struct retrieve_url_ctx* retrieve_url_start_async(struct url* u,
                                                  const char* url_str,
                                                  char** newloc,
                                                  char** file,
                                                  const char* referer,
                                                  int* dt,
                                                  bool recursive,
                                                  struct iri* iri,
                                                  bool initial_url_parsed,
                                                  struct transfer_context* tctx,
                                                  void (*final_cb)(struct retrieve_url_ctx* ctx)) {
  (void)recursive;
  struct retrieve_url_ctx* ctx = xcalloc(1, sizeof(struct retrieve_url_ctx));
  if (!ctx)
    return NULL;

  ctx->u = u;
  ctx->original_url = u;  // For now, original_url is the same as u. It might change during redirects.
  ctx->url = xstrdup(url_str);
  ctx->newloc = newloc;
  ctx->local_file = file;
  ctx->referer = referer;
  ctx->dt = dt;
  ctx->iri = iri;
  ctx->initial_url_parsed = initial_url_parsed;
  ctx->tctx = tctx;
  ctx->final_cb = final_cb;
  ctx->state = RURL_STATE_INIT;
  ctx->redirect_count = 0;
  ctx->free_orig_parsed_url = false;

  if (ctx->tctx) {
    if (!ctx->tctx->has_options)
      transfer_context_snapshot_options(ctx->tctx, &opt);
    if (!ctx->tctx->requested_uri && ctx->url)
      transfer_context_set_requested_uri(ctx->tctx, ctx->url);
    transfer_context_bind_loop(ctx->tctx, wget_ev_loop_get());
    transfer_context_set_state(ctx->tctx, TRANSFER_STATE_TRANSFERRING);
    ctx->tctx->user_data = ctx;  // Link transfer_context to retrieve_url_ctx
  }

  if (!ctx->dt) {
    // If dt is NULL, use local storage.
    ctx->dt = xcalloc(1, sizeof(int));
    *ctx->dt = 0;
  }
  if (ctx->newloc)
    *ctx->newloc = NULL;
  if (ctx->local_file)
    *ctx->local_file = NULL;

  retrieve_url_continue_async(ctx, RETROK);
  return ctx;
}

static void retrieve_url_cleanup(struct retrieve_url_ctx* ctx) {
  if (!ctx)
    return;

  xfree(ctx->url);
  xfree(ctx->proxy);
  if (!ctx->dt_passed_in) {  // Only free if we allocated it
    xfree(ctx->dt);
  }
  if (ctx->free_orig_parsed_url && ctx->original_url) {
    url_free(ctx->original_url);
  }
  if (ctx->u != ctx->original_url)
    url_free(ctx->u);
  iri_free(ctx->iri);
  xfree(ctx);
}

void retrieve_url_continue_async(struct retrieve_url_ctx* ctx, uerr_t prev_op_status) {
  // Check if a previous operation failed, and if so, transition to FAILED state
  if (prev_op_status != RETROK) {
    ctx->result = prev_op_status;
    ctx->state = RURL_STATE_FAILED;
  }

  // State machine loop
  while (ctx->state != RURL_STATE_COMPLETED && ctx->state != RURL_STATE_FAILED) {
    switch (ctx->state) {
      case RURL_STATE_INIT: {
        // This block handles the initial setup and proxy parsing from the original retrieve_url
        char* proxy_str = getproxy(ctx->u);
        if (proxy_str) {
          ctx->proxy = proxy_str;
          struct iri* pi = iri_new();
          set_uri_encoding(pi, opt.locale, true);
          pi->utf8_encode = false;

          ctx->proxy_url = url_parse(ctx->proxy, &ctx->up_error_code, pi, true);
          if (!ctx->proxy_url) {
            logprintf(LOG_NOTQUIET, _("Error parsing proxy URL %s: %s.\n"), ctx->proxy, url_error(ctx->up_error_code));
            ctx->result = PROXERR;
            ctx->state = RURL_STATE_FAILED;
            iri_free(pi);
            break;
          }
          if (ctx->proxy_url->scheme != SCHEME_HTTP && ctx->proxy_url->scheme != ctx->u->scheme) {
            logprintf(LOG_NOTQUIET, _("Error in proxy URL %s: Must be HTTP.\n"), ctx->proxy);
            ctx->result = PROXERR;
            ctx->state = RURL_STATE_FAILED;
            iri_free(pi);
            break;
          }
          iri_free(pi);
        }

        if (ctx->u->scheme == SCHEME_HTTP
#ifdef HAVE_SSL
            || ctx->u->scheme == SCHEME_HTTPS
#endif
            || (ctx->proxy_url && ctx->proxy_url->scheme == SCHEME_HTTP)) {
#ifdef HAVE_HSTS
#ifdef TESTING
          hsts_store_t hsts_store = NULL;
#else
          extern hsts_store_t hsts_store;
#endif

          if (opt.hsts && hsts_store) {
            if (hsts_match(hsts_store, ctx->u))
              logprintf(LOG_VERBOSE, "URL transformed to HTTPS due to an HSTS policy\n");
          }
#endif
          // Proceed to HTTP loop
          ctx->state = RURL_STATE_HTTP_LOOP;
        }
        else {
          logprintf(LOG_NOTQUIET, _("Unsupported URL scheme in %s.\n"), quote(ctx->url));
          ctx->result = URLERROR;
          ctx->state = RURL_STATE_FAILED;
          break;
        }
        // Explicit fallthrough to HTTP_LOOP state
        // fall through
        __attribute__((fallthrough));
      }

      case RURL_STATE_HTTP_LOOP: {
        // This is where http_loop_start_async is called
        // The http_loop_cb will be called when http_loop_start_async completes
        ctx->http_ctx = (struct http_transaction_ctx*)http_loop_start_async(ctx->u, ctx->original_url, ctx->newloc, ctx->local_file, ctx->referer, ctx->dt, ctx->proxy_url, ctx->iri, ctx->tctx,
                                                                            retrieve_url_http_loop_cb);
        if (!ctx->http_ctx) {
          ctx->result = FWRITEERR;  // Or appropriate error
          ctx->state = RURL_STATE_FAILED;
          break;
        }
        // Return from here; the state machine will resume when retrieve_url_http_loop_cb is called.
        return;
      }

      case RURL_STATE_REDIRECT: {
        bool location_changed = (ctx->result == NEWLOCATION || ctx->result == NEWLOCATION_KEEP_POST);
        if (location_changed) {
          char* construced_newloc;
          struct url* newloc_parsed;

          assert(*ctx->newloc != NULL);

          if (*ctx->local_file) {
            xfree(*ctx->local_file);
            *ctx->local_file = NULL;
          }

          construced_newloc = uri_merge(ctx->url, *ctx->newloc ? *ctx->newloc : "");
          xfree(*ctx->newloc);
          *ctx->newloc = construced_newloc;

#ifdef ENABLE_IRI
          ctx->iri->utf8_encode = opt.enable_iri;
          if (opt.encoding_remote)
            set_uri_encoding(ctx->iri, opt.encoding_remote, true);
          set_content_encoding(ctx->iri, NULL);
          xfree(ctx->iri->orig_url);
#endif

          newloc_parsed = url_parse(*ctx->newloc, &ctx->up_error_code, ctx->iri, true);
          if (!newloc_parsed) {
            logprintf(LOG_NOTQUIET, "%s: %s.\n", escnonprint_uri(*ctx->newloc), url_error(ctx->up_error_code));
            ctx->result = WRONGCODE;
            ctx->state = RURL_STATE_FAILED;
            break;
          }

          xfree(*ctx->newloc);
          *ctx->newloc = xstrdup(newloc_parsed->url);

          if (++ctx->redirect_count > opt.max_redirect) {
            logprintf(LOG_NOTQUIET, _("%d redirections exceeded.\n"), opt.max_redirect);
            url_free(newloc_parsed);
            ctx->result = WRONGCODE;
            ctx->state = RURL_STATE_FAILED;
            break;
          }

          xfree(ctx->url);
          ctx->url = *ctx->newloc;
          if (ctx->u != ctx->original_url) {
            url_free(ctx->u);
          }
          ctx->u = newloc_parsed;

          // Re-evaluate proxy and method for the new URL
          // This implicitly re-enters the RURL_STATE_INIT logic for the new URL
          ctx->state = RURL_STATE_INIT;
          continue;  // Loop back to INIT with the new URL
        }
        else {
          xfree(*ctx->newloc);
          *ctx->newloc = NULL;  // Ensure newloc is NULL if not redirected
        }

        // Try to not encode in UTF-8 if fetching failed and IRI is enabled
        if (!(*ctx->dt & RETROKF) && ctx->iri->utf8_encode) {
          ctx->iri->utf8_encode = false;
          if (ctx->u != ctx->original_url) {
            url_free(ctx->u);
          }
          ctx->u = url_parse(ctx->url, NULL, ctx->iri, true);
          if (ctx->u) {
            if (strcmp(ctx->u->url, ctx->original_url->url)) {
              DEBUGP(("[IRI fallbacking to non-utf8 for %s\n", quote(ctx->url)));
              xfree(ctx->url);
              ctx->url = xstrdup(ctx->u->url);
              // Restart process with fallback URL
              ctx->state = RURL_STATE_INIT;
              continue;  // Loop back to INIT with the fallback URL
            }
          }
        }
        ctx->state = RURL_STATE_COMPLETED;  // No more redirects or fallbacks, complete.
        break;
      }

      case RURL_STATE_COMPLETED: {
        if (*ctx->local_file && ctx->u && (*ctx->dt & RETROKF || opt.content_on_error)) {
          register_download(ctx->u->url, *ctx->local_file);

          if (ctx->redirect_count && 0 != strcmp(ctx->original_url->url, ctx->u->url))
            register_redirection(ctx->original_url->url, ctx->u->url);

          if (*ctx->dt & TEXTHTML)
            register_html(*ctx->local_file);

          if (*ctx->dt & TEXTCSS)
            register_css(*ctx->local_file);
        }

        if (ctx->tctx)
          transfer_context_set_local_file(ctx->tctx, *ctx->local_file);

        if (ctx->final_cb)
          ctx->final_cb(ctx);

        if (ctx->tctx) {
          transfer_context_set_state(ctx->tctx, ctx->result == RETROK ? TRANSFER_STATE_COMPLETED : TRANSFER_STATE_FAILED);
        }
        retrieve_url_cleanup(ctx);
        return;  // Exit state machine
      }

      case RURL_STATE_FAILED: {
        if (ctx->tctx) {
          transfer_context_set_state(ctx->tctx, TRANSFER_STATE_FAILED);
        }
        if (ctx->final_cb)
          ctx->final_cb(ctx);
        retrieve_url_cleanup(ctx);
        return;  // Exit state machine
      }
    }
  }
}

static void blocking_final_cb_for_retrieve_url(struct retrieve_url_ctx* ctx);

uerr_t retrieve_url(struct url* orig_parsed,
                    const char* origurl,
                    char** file,
                    char** newloc,
                    const char* refurl,
                    int* dt,
                    bool recursive,
                    struct iri* iri,
                    bool register_status,
                    struct transfer_context* tctx) {
  // This is a blocking wrapper for the asynchronous retrieve_url_start_async
  // It should only be used in contexts where synchronous behavior is absolutely required
  // and there's no event loop available to drive the async operation.
  // For new code, prefer retrieve_url_start_async directly.

  struct ev_loop* loop = EV_DEFAULT;  // Get the default event loop
  g_async_result = -1;
  g_finished = false;

  struct transfer_context local_tctx;
  if (!tctx) {
    transfer_context_prepare(&local_tctx, &opt, origurl);
    tctx = &local_tctx;
  }

  struct retrieve_url_ctx* ctx = retrieve_url_start_async(orig_parsed, origurl, newloc, file, refurl, dt, recursive, iri, register_status, tctx, blocking_final_cb_for_retrieve_url);
  if (!ctx) {
    if (!orig_parsed)
      url_free(orig_parsed);
    if (!dt)
      xfree(dt);
    if (!tctx)
      transfer_context_free(&local_tctx);
    return FWRITEERR;  // Or appropriate error
  }

  g_current_ctx = ctx;

  // Run the event loop until the async operation is finished
  while (!g_finished) {
    ev_run(loop, EVRUN_ONCE);
  }

  if (!tctx) {
    transfer_context_free(&local_tctx);
  }
  if (register_status)
    inform_exit_status(g_async_result);

  return g_async_result;
}

static void retrieve_from_url_list_item_cb(struct retrieve_url_ctx* rurl_ctx) {
  struct retrieve_from_url_list_ctx* ctx = (struct retrieve_from_url_list_ctx*)rurl_ctx->tctx->user_data;
  assert(ctx != NULL);

  ctx->result = rurl_ctx->result;
  if (*rurl_ctx->dt & RETROKF) {
    // Increment count only on successful retrieval
    if (ctx->count)
      (*ctx->count)++;
  }

  // Handle filename cleanup from retrieve_url
  if (*rurl_ctx->local_file && opt.delete_after && file_exists_p(*rurl_ctx->local_file, NULL)) {
    DEBUGP(("\nRemoving file due to --delete-after in retrieve_from_url_list_item_cb():\n"));
    logprintf(LOG_VERBOSE, _("Removing %s.\n"), *rurl_ctx->local_file);
    if (unlink(*rurl_ctx->local_file))
      logprintf(LOG_NOTQUIET, "Failed to unlink %s: (%d) %s\n", *rurl_ctx->local_file, errno, strerror(errno));
  }
  xfree(*rurl_ctx->local_file);
  xfree(*rurl_ctx->newloc);

  // Free the retrieve_url_ctx
  retrieve_url_cleanup(rurl_ctx);
  ctx->rurl_ctx = NULL;

  // Continue to the next URL in the list
  retrieve_from_url_list_continue_async(ctx, ctx->result);
}

static void retrieve_from_url_list_cleanup(struct retrieve_from_url_list_ctx* ctx) {
  if (!ctx)
    return;
  // Note: url_list and iri are managed by the caller (retrieve_from_file or main)
  // We only free the context itself.
  xfree(ctx);
}

struct retrieve_from_url_list_ctx* retrieve_from_url_list_start_async(struct urlpos* url_list, int* count, struct iri* iri, void (*final_cb)(struct retrieve_from_url_list_ctx* ctx)) {
  struct retrieve_from_url_list_ctx* ctx = xcalloc(1, sizeof(struct retrieve_from_url_list_ctx));
  if (!ctx)
    return NULL;

  ctx->url_list = url_list;
  ctx->current_url_pos = url_list;
  ctx->count = count;
  ctx->iri = iri;
  ctx->final_cb = final_cb;
  ctx->state = RURL_LIST_STATE_INIT;
  ctx->result = RETROK;

  retrieve_from_url_list_continue_async(ctx, RETROK);
  return ctx;
}

void retrieve_from_url_list_continue_async(struct retrieve_from_url_list_ctx* ctx, uerr_t prev_op_status) {
  if (prev_op_status != RETROK) {
    ctx->result = prev_op_status;
    ctx->state = RURL_LIST_STATE_FAILED;
  }

  while (ctx->state != RURL_LIST_STATE_COMPLETED && ctx->state != RURL_LIST_STATE_FAILED) {
    switch (ctx->state) {
      case RURL_LIST_STATE_INIT:
      case RURL_LIST_STATE_RETRIEVING_URL: {
        if (ctx->current_url_pos) {
          if (opt.quota && total_downloaded_bytes > opt.quota) {
            ctx->result = QUOTEXC;
            ctx->state = RURL_LIST_STATE_FAILED;
            break;
          }
          if (ctx->current_url_pos->ignore_when_downloading) {
            ctx->current_url_pos = ctx->current_url_pos->next;
            ctx->state = RURL_LIST_STATE_INIT;  // Continue with next URL
            continue;
          }

          struct iri* tmpiri = iri_dup(ctx->iri);
          struct url* parsed_url = url_parse(ctx->current_url_pos->url->url, NULL, tmpiri, true);

          // We pass ctx itself as user_data to transfer_context, so it can be retrieved in the http_loop_cb
          struct transfer_context* tctx = xcalloc(1, sizeof(struct transfer_context));  // Needs to be freed in the callback
          transfer_context_prepare(tctx, &opt, ctx->current_url_pos->url->url);
          tctx->user_data = ctx;  // Link to retrieve_from_url_list_ctx

          // retrieve_url_start_async expects a pointer to char* for newloc and file, so we need local vars
          // that will be updated by retrieve_url and then freed or passed to higher level.
          char* filename_for_rurl = NULL;
          char* newloc_for_rurl = NULL;
          int* dt_for_rurl = xcalloc(1, sizeof(int));

          ctx->rurl_ctx = retrieve_url_start_async(parsed_url ? parsed_url : ctx->current_url_pos->url, ctx->current_url_pos->url->url, &newloc_for_rurl, &filename_for_rurl,
                                                   NULL,  // refurl
                                                   dt_for_rurl, opt.recursive, tmpiri,
                                                   true,  // initial_url_parsed (always true here as we parse it)
                                                   tctx, retrieve_from_url_list_item_cb);
          if (!ctx->rurl_ctx) {
            ctx->result = FWRITEERR;  // Or appropriate error
            ctx->state = RURL_LIST_STATE_FAILED;
            xfree(dt_for_rurl);
            iri_free(tmpiri);
            xfree(tctx);
            break;
          }
          ctx->current_url_pos = ctx->current_url_pos->next;
          ctx->state = RURL_LIST_STATE_RETRIEVING_URL;  // Wait for the current URL retrieval to complete
          return;                                       // Yield control to event loop
        }
        else {
          ctx->state = RURL_LIST_STATE_COMPLETED;
          break;
        }
      }

      case RURL_LIST_STATE_COMPLETED: {
        if (ctx->final_cb)
          ctx->final_cb(ctx);
        retrieve_from_url_list_cleanup(ctx);
        return;
      }
      case RURL_LIST_STATE_FAILED: {
        if (ctx->final_cb)
          ctx->final_cb(ctx);
        retrieve_from_url_list_cleanup(ctx);
        return;
      }
    }
  }
}

// retrieve_from_file async functions
static void retrieve_from_file_rurl_cb(struct retrieve_url_ctx* rurl_ctx) {
  struct retrieve_from_file_ctx* ctx = (struct retrieve_from_file_ctx*)rurl_ctx->tctx->user_data;
  assert(ctx != NULL);

  ctx->result = rurl_ctx->result;
  ctx->url_file_downloaded = *rurl_ctx->local_file;  // Take ownership
  if (*rurl_ctx->dt & TEXTHTML)
    ctx->html = true;

  retrieve_url_cleanup(rurl_ctx);
  ctx->rurl_file_ctx = NULL;

  retrieve_from_file_continue_async(ctx, ctx->result);
}

static void retrieve_from_file_rurl_list_cb(struct retrieve_from_url_list_ctx* rurl_list_ctx) {
  struct retrieve_from_file_ctx* ctx = (struct retrieve_from_file_ctx*)rurl_list_ctx->iri->user_data;  // This is a hack, need better way
  assert(ctx != NULL);

  ctx->result = rurl_list_ctx->result;
  retrieve_from_url_list_cleanup(rurl_list_ctx);
  ctx->rurl_list_ctx = NULL;

  retrieve_from_file_continue_async(ctx, ctx->result);
}

static void retrieve_from_file_cleanup(struct retrieve_from_file_ctx* ctx) {
  if (!ctx)
    return;
  xfree(ctx->url_file_downloaded);
  if (ctx->url_parsed)
    url_free(ctx->url_parsed);
  iri_free(ctx->iri);
  xfree(ctx);
}

struct retrieve_from_file_ctx* retrieve_from_file_start_async(const char* file, bool html, int* count, void (*final_cb)(struct retrieve_from_file_ctx* ctx)) {
  struct retrieve_from_file_ctx* ctx = xcalloc(1, sizeof(struct retrieve_from_file_ctx));
  if (!ctx)
    return NULL;

  ctx->file = file;
  ctx->html = html;
  ctx->count = count;
  ctx->final_cb = final_cb;
  ctx->state = RFILE_STATE_INIT;
  ctx->result = RETROK;
  ctx->iri = iri_new();
  ctx->iri->user_data = ctx;  // Hack to pass ctx to retrieve_from_url_list_cb

  // Reset count
  if (ctx->count)
    *ctx->count = 0;

  // sXXXav : Assume filename and links in the file are in the locale
  set_uri_encoding(ctx->iri, opt.locale, true);
  set_content_encoding(ctx->iri, opt.locale);

  retrieve_from_file_continue_async(ctx, RETROK);
  return ctx;
}

void retrieve_from_file_continue_async(struct retrieve_from_file_ctx* ctx, uerr_t prev_op_status) {
  if (prev_op_status != RETROK) {
    ctx->result = prev_op_status;
    ctx->state = RFILE_STATE_FAILED;
  }

  while (ctx->state != RFILE_STATE_COMPLETED && ctx->state != RFILE_STATE_FAILED) {
    switch (ctx->state) {
      case RFILE_STATE_INIT: {
        ctx->is_url_input_file = url_valid_scheme(ctx->file);
        if (ctx->is_url_input_file) {
          ctx->url_parsed = url_parse(ctx->file, &ctx->up_error_code, ctx->iri, true);
          if (!ctx->url_parsed) {
            logprintf(LOG_NOTQUIET, "%s: %s.\n", ctx->file, url_error(ctx->up_error_code));
            ctx->result = URLERROR;
            ctx->state = RFILE_STATE_FAILED;
            break;
          }

          if (!opt.base_href)
            opt.base_href = xstrdup(ctx->file);

          struct transfer_context* tctx = xcalloc(1, sizeof(struct transfer_context));
          transfer_context_prepare(tctx, &opt, ctx->file);
          tctx->user_data = ctx;  // Link to retrieve_from_file_ctx

          char* local_file_for_rurl = NULL;
          char* newloc_for_rurl = NULL;
          int* dt_for_rurl = xcalloc(1, sizeof(int));

          ctx->rurl_file_ctx = retrieve_url_start_async(ctx->url_parsed, ctx->file, &newloc_for_rurl, &local_file_for_rurl, NULL, dt_for_rurl,
                                                        false,  // recursive
                                                        ctx->iri,
                                                        true,  // initial_url_parsed
                                                        tctx, retrieve_from_file_rurl_cb);
          if (!ctx->rurl_file_ctx) {
            ctx->result = FWRITEERR;
            ctx->state = RFILE_STATE_FAILED;
            xfree(dt_for_rurl);
            xfree(tctx);
            break;
          }
          ctx->input_file = local_file_for_rurl;
          ctx->state = RFILE_STATE_FETCH_URL_FILE;
          return;  // Yield
        }
        else {
          ctx->input_file = (char*)ctx->file;
          ctx->state = RFILE_STATE_GET_URLS_FROM_FILE;
          continue;  // Fall through
        }
      }

      case RFILE_STATE_FETCH_URL_FILE: {
        // If we reached here, the file download for the input URL is complete.
        // Check result from rurl_file_ctx
        if (ctx->result != RETROK || !ctx->url_file_downloaded) {
          ctx->state = RFILE_STATE_FAILED;
          break;
        }
        ctx->input_file = ctx->url_file_downloaded;
        ctx->state = RFILE_STATE_GET_URLS_FROM_FILE;
        // Explicit fallthrough to GET_URLS_FROM_FILE
        // fall through
        __attribute__((fallthrough));
      }

      case RFILE_STATE_GET_URLS_FROM_FILE: {
        struct urlpos* url_list;
        // The original logic had a do-while loop for read_again.
        // This needs to be managed by re-entering this state or a new sub-state.
        url_list = (ctx->html ? get_urls_html(ctx->input_file, NULL, NULL, ctx->iri) : get_urls_file(ctx->input_file, &ctx->read_again));

        if (!url_list && ctx->read_again) {
          // If no URLs but read_again is true, means get_urls_file wants to be called again
          // This should ideally not happen or signify an empty file that needs re-reading.
          // For now, assume it means we are done.
          ctx->state = RFILE_STATE_COMPLETED;
          break;
        }

        ctx->rurl_list_ctx = retrieve_from_url_list_start_async(url_list, ctx->count, ctx->iri, retrieve_from_file_rurl_list_cb);
        if (!ctx->rurl_list_ctx) {
          ctx->result = FWRITEERR;  // Or appropriate error
          ctx->state = RFILE_STATE_FAILED;
          if (url_list)
            free_urlpos(url_list);
          break;
        }
        ctx->state = RFILE_STATE_RETRIEVING_URL_LIST;
        return;  // Yield
      }

      case RFILE_STATE_RETRIEVING_URL_LIST: {
        // If we reached here, the URL list retrieval is complete.
        // The result is already in ctx->result from retrieve_from_file_rurl_list_cb.
        if (ctx->read_again) {
          // If read_again is true, we need to go back and get URLs from file again
          ctx->state = RFILE_STATE_GET_URLS_FROM_FILE;
          continue;
        }
        else {
          ctx->state = RFILE_STATE_COMPLETED;
          break;
        }
      }

      case RFILE_STATE_COMPLETED: {
        xfree(ctx->input_file);
        // Note: url_list is freed by retrieve_from_url_list_cleanup
        if (ctx->final_cb)
          ctx->final_cb(ctx);
        retrieve_from_file_cleanup(ctx);
        return;
      }
      case RFILE_STATE_FAILED: {
        if (ctx->final_cb)
          ctx->final_cb(ctx);
        retrieve_from_file_cleanup(ctx);
        return;
      }
    }
  }
}

static uerr_t g_async_result_rurl_list WGET_ATTR_UNUSED = RETROK;
static bool g_finished_rurl_list WGET_ATTR_UNUSED = false;

static uerr_t g_async_result_rfile = RETROK;
static bool g_finished_rfile = false;

static void blocking_final_cb_for_retrieve_from_file(struct retrieve_from_file_ctx* ctx) {
  g_async_result_rfile = ctx->result;
  g_finished_rfile = true;
}

uerr_t retrieve_from_file(const char* file, bool html, int* count) {
  // Blocking wrapper for retrieve_from_file_start_async
  g_async_result_rfile = RETROK;
  g_finished_rfile = false;

  struct retrieve_from_file_ctx* ctx = retrieve_from_file_start_async(file, html, count, blocking_final_cb_for_retrieve_from_file);
  if (!ctx) {
    return FWRITEERR;
  }

  while (!g_finished_rfile) {
    ev_run(EV_DEFAULT, EVRUN_ONCE);
  }

  return g_async_result_rfile;
}

/* Print `giving up', or `retrying', depending on the impending
   action.  N1 and N2 are the attempt number and the attempt limit.  */
void printwhat(int n1, int n2) {
  logputs(LOG_VERBOSE, (n1 == n2) ? _("Giving up.\n\n") : _("Retrying.\n\n"));
}

/* Async version using scheduler timers */
typedef struct {
  scheduler_timer_cb_t callback;
  void* user_arg;
} sleep_callback_data_t;

static void sleep_between_retrievals_async_cb(void* user_arg) {
  sleep_callback_data_t* data = user_arg;
  if (data && data->callback) {
    data->callback(data->user_arg);
  }
  xfree(data);
}

int sleep_between_retrievals_async(scheduler_t* sched, int count, scheduler_timer_cb_t callback, void* user_arg) {
  static bool first_retrieval = true;
  double wait_seconds = 0;

  if (first_retrieval) {
    /* Don't sleep before the very first retrieval. */
    first_retrieval = false;
    return SCHED_ERR_INVALID; /* No sleep needed */
  }

  if (opt.waitretry && count > 1) {
    /* If opt.waitretry is specified and this is a retry, wait for
       COUNT-1 number of seconds, or for opt.waitretry seconds.  */
    if (count <= opt.waitretry)
      wait_seconds = count - 1;
    else
      wait_seconds = opt.waitretry;
  }
  else if (opt.wait) {
    if (!opt.random_wait || count > 1) {
      /* If random-wait is not specified, or if we are sleeping
         between retries of the same download, sleep the fixed
         interval.  */
      wait_seconds = opt.wait;
    }
    else {
      /* Sleep a random amount of time averaging in opt.wait
         seconds.  The sleeping amount ranges from 0.5*opt.wait to
         1.5*opt.wait.  */
      wait_seconds = (0.5 + random_float()) * opt.wait;
      DEBUGP(("sleep_between_retrievals_async: avg=%f,sleep=%f\n", opt.wait, wait_seconds));
    }
  }

  if (wait_seconds > 0) {
    sleep_callback_data_t* data = xcalloc(1, sizeof(*data));
    data->callback = callback;
    data->user_arg = user_arg;

    return scheduler_delay(sched, wait_seconds, sleep_between_retrievals_async_cb, data);
  }

  return SCHED_ERR_INVALID; /* No sleep needed */
}

/* Free the linked list of urlpos.  */
void free_urlpos(struct urlpos* l) {
  while (l) {
    struct urlpos* next = l->next;
    if (l->url)
      url_free(l->url);
    xfree(l->local_name);
    xfree(l);
    l = next;
  }
}

/* Rotate FNAME opt.backups times */
void rotate_backups(const char* fname) {
#define SEP "."
#define FILE_BUF_SIZE 1024

  /* avoid alloca() here */
  char from[FILE_BUF_SIZE], to[FILE_BUF_SIZE];
  struct stat sb;
  bool overflow;
  int i;

  if (stat(fname, &sb) == 0)
    if (S_ISREG(sb.st_mode) == 0)
      return;

  for (i = opt.backups; i > 1; i--) {
    overflow = (unsigned)snprintf(to, FILE_BUF_SIZE, "%s%s%d", fname, SEP, i) >= FILE_BUF_SIZE;
    overflow |= (unsigned)snprintf(from, FILE_BUF_SIZE, "%s%s%d", fname, SEP, i - 1) >= FILE_BUF_SIZE;

    if (overflow)
      errno = ENAMETOOLONG;
    if (overflow || rename(from, to)) {
      /* The original file may not exist. In which case rename() will
       * return ENOENT. This is not a real error. We could make this better
       * by calling stat() first and making sure that the file exists. */
      if (errno != ENOENT)
        logprintf(LOG_NOTQUIET, "Failed to rename %s to %s: (%d) %s\n", from, to, errno, strerror(errno));
    }
  }

  overflow = (unsigned)snprintf(to, FILE_BUF_SIZE, "%s%s%d", fname, SEP, 1) >= FILE_BUF_SIZE;
  if (overflow)
    errno = ENAMETOOLONG;
  if (overflow || rename(fname, to)) {
    if (errno != ENOENT)
      logprintf(LOG_NOTQUIET, "Failed to rename %s to %s: (%d) %s\n", from, to, errno, strerror(errno));
  }

#undef FILE_BUF_SIZE
#undef SEP
}

static bool no_proxy_match(const char*, const char**);

/* Return the URL of the proxy appropriate for url U.  */

static char* getproxy(struct url* u) {
  char* proxy = NULL;
  char* rewritten_url;

  if (!opt.use_proxy)
    return NULL;
  if (no_proxy_match(u->host, (const char**)opt.no_proxy))
    return NULL;

  switch (u->scheme) {
    case SCHEME_HTTP:
      proxy = opt.http_proxy ? opt.http_proxy : getenv("http_proxy");
      break;
#ifdef HAVE_SSL
    case SCHEME_HTTPS:
      proxy = opt.https_proxy ? opt.https_proxy : getenv("https_proxy");
      break;
#endif
    case SCHEME_INVALID:
      break;
  }
  if (!proxy || !*proxy)
#ifdef HAVE_LIBPROXY
  {
    pxProxyFactory* pf = px_proxy_factory_new();
    if (!pf) {
      DEBUGP(("Allocating memory for libproxy failed"));
      return NULL;
    }

    DEBUGP(("asking libproxy about url '%s'\n", u->url));
    char** proxies = px_proxy_factory_get_proxies(pf, u->url);
    if (proxies) {
      if (proxies[0]) {
        DEBUGP(("libproxy suggest to use '%s'\n", proxies[0]));
        if (strcmp(proxies[0], "direct://") != 0) {
          proxy = xstrdup(proxies[0]);
          DEBUGP(("libproxy setting to use '%s'\n", proxy));
        }
      }

      px_proxy_factory_free_proxies(proxies);
    }
    px_proxy_factory_free(pf);

    if (!proxy || !*proxy)
      return NULL;
  }
#else
    return NULL;
#endif

  /* Handle shorthands.  `rewritten_storage' is a kludge to allow
     getproxy() to return static storage. */
  rewritten_url = maybe_prepend_scheme(proxy);
  if (rewritten_url)
    return rewritten_url;

  return strdup(proxy);
}

/* Returns true if URL would be downloaded through a proxy. */

bool url_uses_proxy(struct url* u) {
  bool ret;
  char* proxy;

  if (!u)
    return false;
  proxy = getproxy(u);
  ret = proxy != NULL;
  xfree(proxy);
  return ret;
}

/* Should a host be accessed through proxy, concerning no_proxy?  */
static bool no_proxy_match(const char* host, const char** no_proxy) {
  if (!no_proxy)
    return false;
  else
    return sufmatch(no_proxy, host);
}

/* Set the file parameter to point to the local file string.  */
void set_local_file(const char** file, const char* default_file) {
  if (opt.output_document) {
    if (output_stream_regular)
      *file = opt.output_document;
  }
  else
    *file = default_file;
}

/* Return true for an input file's own URL, false otherwise.  */
bool input_file_url(const char* input_file) {
  static bool first = true;

  if (input_file && url_has_scheme(input_file) && first) {
    first = false;
    return true;
  }
  else
    return false;
}

#ifdef TESTING

#include <stdint.h>
#include "../tests/unit-tests.h"

const char* test_retr_rate(void) {
  static const struct test {
    wgint bytes;
    double secs;
    const char* expected;
  } tests[] = {
      {0, 1, "0.00 B/s"},
      {INT64_MAX, 1, "100 TB/s"},
  };

  for (struct test* t = tests; t < tests + countof(tests); t++) {
    const char* result = retr_rate(t->bytes, t->secs);

    if (strcmp(result, t->expected))
      return aprintf("%s: Expected '%s', got '%s'", __func__, t->expected, result);
  }

  return NULL;
}

#endif /* TESTING */
