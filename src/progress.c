/* Download progress tracking and display
 * src/progress.c
 */

#include "wget.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c-strcase.h"
#include "progress.h"
#include "retr.h"
#include "threading.h"
#include "utils.h"

struct progress_implementation {
  const char* name;
  bool interactive;
  void* (*create)(const char* file, wgint initial, wgint total);
  void (*update)(void* progress, wgint howmuch, double dltime);
  void (*draw)(void* progress);
  void (*finish)(void* progress, double dltime);
  void (*set_params)(const char* params);
};

/* forward declarations for dot/bar backends */

static void* dot_create(const char* f_download, wgint initial, wgint total);
static void dot_update(void* progress, wgint howmuch, double dltime);
static void dot_finish(void* progress, double dltime);
static void dot_draw(void* progress);
static void dot_set_params(const char* params);

static void* bar_create(const char* f_download, wgint initial, wgint total);
static void bar_update(void* progress, wgint howmuch, double dltime);
static void bar_draw(void* progress);
static void bar_finish(void* progress, double dltime);
static void bar_set_params(const char* params);

static const struct progress_implementation implementations[] = {
    {"dot", false, dot_create, dot_update, dot_draw, dot_finish, dot_set_params},
    {"bar", true, bar_create, bar_update, bar_draw, bar_finish, bar_set_params},
};

static struct progress_implementation* current_impl;
static int current_impl_locked;
static wget_mutex_t progress_mutex;

static void progress_lock(void) {
  static bool initialized = false;
  if (!initialized) {
    wget_mutex_init(&progress_mutex);
    initialized = true;
  }
  wget_mutex_lock(&progress_mutex);
}

static void progress_unlock(void) {
  wget_mutex_unlock(&progress_mutex);
}

/* default progress backend, overridable via config or CLI */

#define DEFAULT_PROGRESS_IMPLEMENTATION "bar"

/* noninteractive fallback for redirected logs or non-tty stderr */

#define FALLBACK_PROGRESS_IMPLEMENTATION "dot"

/* Return true if NAME selects a known progress implementation
 * any suffix after ':' is ignored
 */

bool valid_progress_implementation_p(const char* name) {
  size_t i;
  const struct progress_implementation* pi = implementations;
  const char* colon = strchr(name, ':');
  size_t namelen = colon ? (size_t)(colon - name) : strlen(name);

  for (i = 0; i < countof(implementations); i++, pi++) {
    if (!strncmp(pi->name, name, namelen))
      return true;
  }
  return false;
}

/* Select active progress implementation by name (with optional :params) */

void set_progress_implementation(const char* name) {
  size_t i, namelen;
  struct progress_implementation* pi = (struct progress_implementation*)implementations;
  const char* colon;

  progress_lock();

  if (!name)
    name = DEFAULT_PROGRESS_IMPLEMENTATION;

  colon = strchr(name, ':');
  namelen = colon ? (size_t)(colon - name) : strlen(name);

  for (i = 0; i < countof(implementations); i++, pi++) {
    if (!strncmp(pi->name, name, namelen)) {
      current_impl = pi;
      current_impl_locked = 0;

      if (colon)
        ++colon;

      if (pi->set_params)
        pi->set_params(colon);

      progress_unlock();
      return;
    }
  }

  progress_unlock();
  abort();
}

static volatile sig_atomic_t output_redirected;

void progress_schedule_redirect(void) {
  output_redirected = 1;
}

/* Create a progress gauge
 * INITIAL is the starting byte offset (0 for fresh downloads)
 * TOTAL is the expected total size, or 0 if unknown
 */

void* progress_create(const char* f_download, wgint initial, wgint total) {
  void* progress;

  progress_lock();

  /* switch to a simple progress style if logging was redirected */
  if (output_redirected) {
    if (!current_impl_locked)
      set_progress_implementation(FALLBACK_PROGRESS_IMPLEMENTATION);
    output_redirected = 0;
  }

  progress = current_impl->create(f_download, initial, total);
  progress_unlock();
  return progress;
}

/* Return true if the current progress backend benefits from periodic redraws */

bool progress_interactive_p(void* progress WGET_ATTR_UNUSED) {
  bool interactive;

  progress_lock();
  interactive = current_impl->interactive;
  progress_unlock();
  return interactive;
}

/* Inform the progress gauge of newly received bytes
 * DLTIME is seconds since the transfer started
 */

void progress_update(void* progress, wgint howmuch, double dltime) {
  /* sanitize input */
  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;

  if (howmuch < 0)
    howmuch = 0;

  progress_lock();
  current_impl->update(progress, howmuch, dltime);
  current_impl->draw(progress);
  progress_unlock();
}

/* Finalize a progress gauge and release its resources */

void progress_finish(void* progress, double dltime) {
  /* sanitize input */
  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;

  progress_lock();
  current_impl->finish(progress, dltime);
  progress_unlock();
}

/* Dot-printing backend */

struct dot_progress {
  wgint initial_length; /* bytes already on disk before this run */
  wgint total_length;   /* expected final size, 0 if unknown */

  wgint accumulated; /* bytes collected since last printed dot */

  double dltime; /* total download time so far */
  wgint rows;    /* completed rows */
  int dots;      /* dots in current row */

  double last_timer_value;
};

static const char* eta_to_human_short(int secs, bool condensed);

/* minimal rows increment when coalescing multiple rows of dots */

#ifndef ADD_DOT_ROWS_THRS
#define ADD_DOT_ROWS_THRS 2
#endif

/* Print one line of stats for the current dot row
 * includes percentage, instantaneous rate, and ETA or total time
 */

static void
#if ADD_DOT_ROWS_THRS
print_row_stats(struct dot_progress* dp, double dltime, bool last, wgint added_rows)
#else
print_row_stats(struct dot_progress* dp, double dltime, bool last)
#endif
{
  const wgint ROW_BYTES = opt.dot_bytes * opt.dots_in_line;
  wgint bytes_displayed = dp->rows * ROW_BYTES + dp->dots * opt.dot_bytes;

  if (last)
    bytes_displayed += dp->accumulated;

  if (bytes_displayed < 0)
    bytes_displayed = 0;

  if (dp->total_length) {
    int percentage = 100.0 * bytes_displayed / dp->total_length;
    logprintf(LOG_PROGRESS, "%3d%%", percentage);
  }

  /* instantaneous row rate */
  {
    static char names[] = {' ', 'K', 'M', 'G', 'T'};
    int units;
    double rate;
    wgint bytes_this_row;

    if (!last)
#if ADD_DOT_ROWS_THRS
      bytes_this_row = ROW_BYTES * added_rows;
#else
      bytes_this_row = ROW_BYTES;
#endif
    else
      bytes_this_row = dp->dots * opt.dot_bytes + dp->accumulated;

    if (dp->rows == dp->initial_length / ROW_BYTES)
      bytes_this_row -= dp->initial_length % ROW_BYTES;

    rate = calc_rate(bytes_this_row, dltime - dp->last_timer_value, &units);
    logprintf(LOG_PROGRESS, " %4.*f%c", rate >= 99.95 ? 0 : rate >= 9.995 ? 1 : 2, rate, names[units]);
    dp->last_timer_value = dltime;
  }

  if (!last) {
    if (dp->total_length) {
      wgint bytes_remaining = dp->total_length > bytes_displayed ? dp->total_length - bytes_displayed : 0;
      wgint bytes_sofar = bytes_displayed > dp->initial_length ? bytes_displayed - dp->initial_length : 1;
      double eta = dltime * bytes_remaining / bytes_sofar;
      if (eta < 0)
        eta = 0;
      if (eta < INT_MAX - 1)
        logprintf(LOG_PROGRESS, " %s", eta_to_human_short((int)(eta + 0.5), true));
    }
  }
  else {
    if (dltime >= 10)
      logprintf(LOG_PROGRESS, "=%s", eta_to_human_short((int)(dltime + 0.5), true));
    else
      logprintf(LOG_PROGRESS, "=%ss", print_decimal(dltime));
  }
}

/* dot backend: create */

static void* dot_create(const char* f_download WGET_ATTR_UNUSED, wgint initial, wgint total) {
  struct dot_progress* dp = xnew0(struct dot_progress);
  dp->initial_length = initial;
  dp->total_length = total;

  if (dp->initial_length) {
    int dot_bytes = opt.dot_bytes;
    const wgint ROW_BYTES = opt.dot_bytes * opt.dots_in_line;

    int remainder = dp->initial_length % ROW_BYTES;
    wgint skipped = dp->initial_length - remainder;

    if (skipped) {
      wgint skipped_k = skipped / 1024;
      int skipped_k_len = numdigit(skipped_k);
      if (skipped_k_len < 6)
        skipped_k_len = 6;

      /* align skip line with dot columns */
      logprintf(LOG_PROGRESS, _("\n%*s[ skipping %sK ]"), 2 + skipped_k_len, "", number_to_static_string(skipped_k));
    }

    logprintf(LOG_PROGRESS, "\n%6sK", number_to_static_string(skipped / 1024));
    for (; remainder >= dot_bytes; remainder -= dot_bytes) {
      if (dp->dots % opt.dot_spacing == 0)
        logputs(LOG_PROGRESS, " ");
      logputs(LOG_PROGRESS, ",");
      ++dp->dots;
    }
    assert(dp->dots < opt.dots_in_line);

    dp->accumulated = remainder;
    dp->rows = skipped / ROW_BYTES;
  }

  return dp;
}

/* dot backend: update accumulation, redraw happens in dot_draw */

static void dot_update(void* progress, wgint howmuch, double dltime) {
  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;

  if (howmuch < 0)
    howmuch = 0;

  struct dot_progress* dp = progress;
  dp->accumulated += howmuch;
  dp->dltime = dltime;
}

/* dot backend: draw one or more dots */

static void dot_draw(void* progress) {
  struct dot_progress* dp = progress;
  int dot_bytes = opt.dot_bytes;
  wgint ROW_BYTES = opt.dot_bytes * opt.dots_in_line;

  log_set_flush(false);

  while (dp->accumulated >= dot_bytes) {
    dp->accumulated -= dot_bytes;
    if (dp->dots == 0)
      logprintf(LOG_PROGRESS, "\n%6sK", number_to_static_string(dp->rows * ROW_BYTES / 1024));

    if (dp->dots % opt.dot_spacing == 0)
      logputs(LOG_PROGRESS, " ");
    logputs(LOG_PROGRESS, ".");

    ++dp->dots;
    if (dp->dots >= opt.dots_in_line) {
      dp->dots = 0;
#if ADD_DOT_ROWS_THRS
      {
        wgint added_rows = 1;
        if (dp->accumulated >= (ROW_BYTES << ADD_DOT_ROWS_THRS)) {
          added_rows += dp->accumulated / ROW_BYTES;
          dp->accumulated %= ROW_BYTES;
        }
        if (WGINT_MAX - dp->rows >= added_rows)
          dp->rows += added_rows;
        else
          dp->rows = WGINT_MAX;
        print_row_stats(dp, dp->dltime, false, added_rows);
      }
#else
      if (dp->rows < WGINT_MAX)
        ++dp->rows;
      print_row_stats(dp, dp->dltime, false);
#endif
    }
  }

  log_set_flush(true);
}

/* dot backend: finalize and print last row summary */

static void dot_finish(void* progress, double dltime) {
  struct dot_progress* dp = progress;
  wgint ROW_BYTES = opt.dot_bytes * opt.dots_in_line;
  int i;

  log_set_flush(false);

  if (dp->dots == 0)
    logprintf(LOG_PROGRESS, "\n%6sK", number_to_static_string(dp->rows * ROW_BYTES / 1024));
  for (i = dp->dots; i < opt.dots_in_line; i++) {
    if (i % opt.dot_spacing == 0)
      logputs(LOG_PROGRESS, " ");
    logputs(LOG_PROGRESS, " ");
  }

  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;
#if ADD_DOT_ROWS_THRS
  print_row_stats(dp, dltime, true, 1);
#else
  print_row_stats(dp, dltime, true);
#endif
  logputs(LOG_PROGRESS, "\n\n");
  log_set_flush(true);

  xfree(dp);
}

/* Interpret dot progress parameters
 * --progress=dot:style where style is one of:
 *   default, binary, mega, giga
 */

static void dot_set_params(const char* params) {
  current_impl->interactive = false;
  if (!params || !*params)
    params = opt.dot_style;

  if (!params)
    return;

  if (!c_strcasecmp(params, "default")) {
    /* 1K dots, 10 per cluster, 50 per line */
    opt.dot_bytes = 1024;
    opt.dot_spacing = 10;
    opt.dots_in_line = 50;
  }
  else if (!c_strcasecmp(params, "binary")) {
    /* 8K dots, 16 per cluster, 48 per line */
    opt.dot_bytes = 8192;
    opt.dot_spacing = 16;
    opt.dots_in_line = 48;
  }
  else if (!c_strcasecmp(params, "mega")) {
    /* 64K dots, 8 per cluster, 3M per line */
    opt.dot_bytes = 65536L;
    opt.dot_spacing = 8;
    opt.dots_in_line = 48;
  }
  else if (!c_strcasecmp(params, "giga")) {
    /* 1M dots, 8 per cluster, 32M per line */
    opt.dot_bytes = (1L << 20);
    opt.dot_spacing = 8;
    opt.dots_in_line = 32;
  }
  else
    fprintf(stderr, _("Invalid dot style specification %s; leaving unchanged\n"), quote(params));
}

/* "Thermometer" (bar) progress backend */

#define DEFAULT_SCREEN_WIDTH 80
#define MINIMUM_SCREEN_WIDTH 51

static int screen_width;
static volatile sig_atomic_t received_sigwinch;

/* ring buffer size for recent throughput samples */

#define DLSPEED_HISTORY_SIZE 20

/* minimal duration of a single history sample in seconds */

#define DLSPEED_SAMPLE_MIN 0.15

/* time after which a quiet connection is treated as stalled */

#define STALL_START_TIME 5

/* minimum interval between redraws */

#define REFRESH_INTERVAL 0.2

/* minimum interval between ETA recomputations */

#define ETA_REFRESH_INTERVAL 0.99

struct bar_progress {
  char* f_download;
  wgint initial_length;
  wgint total_length;
  wgint count;

  double last_screen_update;

  double dltime;
  int width;
  char* buffer;
  int tick;

  struct bar_progress_hist {
    int pos;
    double times[DLSPEED_HISTORY_SIZE];
    wgint bytes[DLSPEED_HISTORY_SIZE];

    double total_time;
    wgint total_bytes;
  } hist;

  double recent_start;
  wgint recent_bytes;

  bool stalled;

  double last_eta_time;
  int last_eta_value;
};

static void create_image(struct bar_progress* bp, double dl_total_time, bool done);
static void display_image(char* buf);

static size_t prepare_filename(char* dest, const char* src) {
  size_t ret = 1;

  if (src) {
    while (*src) {
      if (!iscntrl((unsigned char)*src)) {
        if (dest)
          *dest++ = *src;
        ret++;
      }
      else {
        if (dest)
          dest += sprintf(dest, "%%%02x", (unsigned char)*src);
        ret += 3;
      }
      src++;
    }
  }
  if (dest)
    *dest = 0;
  return ret;
}

static void* bar_create(const char* f_download, wgint initial, wgint total) {
  struct bar_progress* bp = xnew0(struct bar_progress);

  if (initial > total)
    total = initial;

  bp->initial_length = initial;
  bp->total_length = total;

  bp->f_download = xmalloc(prepare_filename(NULL, f_download));
  prepare_filename(bp->f_download, f_download);

  /* discover usable screen width or fall back to defaults */
  if (!screen_width || received_sigwinch) {
    screen_width = determine_screen_width();
    if (!screen_width)
      screen_width = DEFAULT_SCREEN_WIDTH;
    else if (screen_width < MINIMUM_SCREEN_WIDTH)
      screen_width = MINIMUM_SCREEN_WIDTH;
    received_sigwinch = 0;
  }

  /* avoid using the last column to reduce wrapping odds */
  bp->width = screen_width - 1;

#define BUF_LEN (bp->width * 2 + 100)
  bp->buffer = xcalloc(BUF_LEN, 1);

  logputs(LOG_VERBOSE, "\n");

  create_image(bp, 0, false);
  display_image(bp->buffer);

  return bp;
}

static void update_speed_ring(struct bar_progress* bp, wgint howmuch, double dltime);

/* bar backend: update counters and speed history */

static void bar_update(void* progress, wgint howmuch, double dltime) {
  struct bar_progress* bp = progress;

  bp->dltime = dltime;
  if (WGINT_MAX - (bp->count + bp->initial_length) >= howmuch)
    bp->count += howmuch;
  else
    bp->count = WGINT_MAX - bp->initial_length;

  if (bp->total_length > 0 && bp->count + bp->initial_length > bp->total_length)
    bp->total_length = bp->initial_length + bp->count;

  update_speed_ring(bp, howmuch, dltime);
}

/* bar backend: redraw if enough time has passed or the terminal resized */

static void bar_draw(void* progress) {
  bool force_screen_update = false;
  struct bar_progress* bp = progress;

  if (received_sigwinch) {
    int old_width = screen_width;
    screen_width = determine_screen_width();
    if (!screen_width)
      screen_width = DEFAULT_SCREEN_WIDTH;
    else if (screen_width < MINIMUM_SCREEN_WIDTH)
      screen_width = MINIMUM_SCREEN_WIDTH;
    if (screen_width != old_width) {
      bp->width = screen_width - 1;
      bp->buffer = xrealloc(bp->buffer, BUF_LEN);
      force_screen_update = true;
    }
    received_sigwinch = 0;
  }

  if (bp->dltime - bp->last_screen_update < REFRESH_INTERVAL && !force_screen_update)
    return;

  create_image(bp, bp->dltime, false);
  display_image(bp->buffer);
  bp->last_screen_update = bp->dltime;
}

/* bar backend: finalize display and free state */

static void bar_finish(void* progress, double dltime) {
  struct bar_progress* bp = progress;

  if (bp->total_length > 0 && bp->count + bp->initial_length > bp->total_length)
    bp->total_length = bp->initial_length + bp->count;

  create_image(bp, dltime, true);
  display_image(bp->buffer);

  logputs(LOG_VERBOSE, "\n");
  logputs(LOG_PROGRESS, "\n");

  xfree(bp->f_download);
  xfree(bp->buffer);
  xfree(bp);
}

/* maintain a rolling notion of current download speed over several seconds */

static void update_speed_ring(struct bar_progress* bp, wgint howmuch, double dltime) {
  struct bar_progress_hist* hist = &bp->hist;
  double recent_age = dltime - bp->recent_start;

  bp->recent_bytes += howmuch;

  if (recent_age < DLSPEED_SAMPLE_MIN)
    return;

  if (howmuch == 0) {
    if (recent_age >= STALL_START_TIME) {
      bp->stalled = true;
      xzero(*hist);
      bp->recent_bytes = 0;
    }
    return;
  }

  if (bp->stalled) {
    bp->stalled = false;
    recent_age = 1;
  }

  hist->total_time -= hist->times[hist->pos];
  hist->total_bytes -= hist->bytes[hist->pos];

  hist->times[hist->pos] = recent_age;
  hist->bytes[hist->pos] = bp->recent_bytes;
  hist->total_time += recent_age;
  hist->total_bytes += bp->recent_bytes;

  bp->recent_start = dltime;
  bp->recent_bytes = 0;

  if (++hist->pos == DLSPEED_HISTORY_SIZE)
    hist->pos = 0;
}

/* these helpers treat strings as simple 1-byte-per-column for now */

static int count_cols(const char* mbs) {
  return (int)strlen(mbs);
}

static int cols_to_bytes(const char* mbs, const int cols, int* ncols) {
  int len = (int)strlen(mbs);
  int ret = len < cols ? len : cols;
  *ncols = ret;
  return ret;
}

static const char* get_eta(int* bcd) {
  static const char eta_str[] = N_("    eta %s");
  static const char* eta_trans;
  static int bytes_cols_diff;

  if (eta_trans == NULL) {
    int nbytes = (int)strlen(eta_str);
    int ncols = count_cols(eta_str);
    eta_trans = eta_str;
    bytes_cols_diff = nbytes - ncols;
  }

  if (bcd)
    *bcd = bytes_cols_diff;

  return eta_trans;
}

#define APPEND_LITERAL(s)        \
  do {                           \
    memcpy(p, s, sizeof(s) - 1); \
    p += sizeof(s) - 1;          \
  } while (0)

/* Render the current state into bp->buffer as a single progress line */

static void create_image(struct bar_progress* bp, double dl_total_time, bool done) {
  const int MAX_FILENAME_COLS = bp->width / 4;
  char* p = bp->buffer;
  wgint size = bp->initial_length + bp->count;

  struct bar_progress_hist* hist = &bp->hist;
  int orig_filename_cols = count_cols(bp->f_download);

  int padding;

#define PROGRESS_FILENAME_LEN (MAX_FILENAME_COLS + 1)
#define PROGRESS_PERCENT_LEN 4
#define PROGRESS_DECORAT_LEN 2
#define PROGRESS_FILESIZE_LEN (7 + 1)
#define PROGRESS_DWNLOAD_RATE (8 + 2)
#define PROGRESS_ETA_LEN 15

  int progress_size = bp->width - (PROGRESS_FILENAME_LEN + PROGRESS_PERCENT_LEN + PROGRESS_DECORAT_LEN + PROGRESS_FILESIZE_LEN + PROGRESS_DWNLOAD_RATE + PROGRESS_ETA_LEN);

  int bytes_cols_diff = 0;
  int cols_diff;
  const char* down_size;

  if (progress_size < 5)
    progress_size = 0;

  if (dl_total_time >= INT_MAX)
    dl_total_time = INT_MAX - 1;
  else if (dl_total_time < 0)
    dl_total_time = 0;

  /* filename column, possibly scrolled */

  if (orig_filename_cols < MAX_FILENAME_COLS) {
    p += sprintf(p, "%s", bp->f_download);
    padding = MAX_FILENAME_COLS - orig_filename_cols + 1;
    memset(p, ' ', padding);
    p += padding;
  }
  else {
    int offset_cols;
    int bytes_in_filename, offset_bytes, col;
    int* cols_ret = &col;

#define MIN_SCROLL_TEXT 5
    if ((orig_filename_cols > MAX_FILENAME_COLS + MIN_SCROLL_TEXT) && !opt.noscroll && !done) {
      offset_cols = ((int)bp->tick + orig_filename_cols + MAX_FILENAME_COLS / 2) % (orig_filename_cols + MAX_FILENAME_COLS);
      if (offset_cols > orig_filename_cols) {
        padding = MAX_FILENAME_COLS - (offset_cols - orig_filename_cols);
        memset(p, ' ', padding);
        p += padding;
        offset_cols = 0;
      }
      else
        padding = 0;
    }
    else {
      padding = 0;
      offset_cols = 0;
    }

    offset_bytes = cols_to_bytes(bp->f_download, offset_cols, cols_ret);
    bytes_in_filename = cols_to_bytes(bp->f_download + offset_bytes, MAX_FILENAME_COLS - padding, cols_ret);
    memcpy(p, bp->f_download + offset_bytes, (size_t)bytes_in_filename);
    p += bytes_in_filename;
    padding = MAX_FILENAME_COLS - (padding + *cols_ret);
    memset(p, ' ', padding + 1);
    p += padding + 1;
  }

  /* percentage */

  if (bp->total_length > 0) {
    int percentage = 100.0 * size / bp->total_length;
    assert(percentage <= 100);
    p += sprintf(p, "%3d%%", percentage);
  }
  else {
    memset(p, ' ', PROGRESS_PERCENT_LEN);
    p += PROGRESS_PERCENT_LEN;
  }

  /* progress bar body */

  if (progress_size && bp->total_length > 0) {
    int insz = (int)((double)bp->initial_length / bp->total_length * progress_size);
    int dlsz = (int)((double)size / bp->total_length * progress_size);
    char* begin;

    assert(dlsz <= progress_size);
    assert(insz <= dlsz);

    *p++ = '[';
    begin = p;

    memset(p, '+', insz);
    p += insz;

    dlsz -= insz;
    if (dlsz > 0) {
      memset(p, '=', dlsz - 1);
      p += dlsz - 1;
      *p++ = '>';
    }

    memset(p, ' ', (size_t)(progress_size - (p - begin)));
    p += progress_size - (p - begin);
    *p++ = ']';
  }
  else if (progress_size) {
    int ind = bp->tick % (progress_size * 2 - 6);
    int i, pos;

    if (ind < progress_size - 2)
      pos = ind + 1;
    else
      pos = progress_size - (ind - progress_size + 5);

    *p++ = '[';
    for (i = 0; i < progress_size; i++) {
      if (i == pos - 1)
        *p++ = '<';
      else if (i == pos)
        *p++ = '=';
      else if (i == pos + 1)
        *p++ = '>';
      else
        *p++ = ' ';
    }
    *p++ = ']';
  }
  ++bp->tick;

  /* downloaded size, human readable */

  down_size = human_readable(size, 1000, 2);
  cols_diff = PROGRESS_FILESIZE_LEN - count_cols(down_size);
  if (cols_diff > 0) {
    memset(p, ' ', (size_t)cols_diff);
    p += cols_diff;
  }
  p += sprintf(p, "%s", down_size);

  /* rate */

  if (hist->total_time > 0 && hist->total_bytes) {
    static const char* short_units[] = {" B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
    static const char* short_units_bits[] = {" b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"};
    int units = 0;
    wgint dlquant = hist->total_bytes + bp->recent_bytes;
    double dltime = hist->total_time + (dl_total_time - bp->recent_start);
    double dlspeed = calc_rate(dlquant, dltime, &units);

    p += sprintf(p, "  %4.*f%s", dlspeed >= 99.95 ? 0 : dlspeed >= 9.995 ? 1 : 2, dlspeed, !opt.report_bps ? short_units[units] : short_units_bits[units]);
  }
  else
    APPEND_LITERAL("  --.-KB/s");

  /* ETA or total time */

  if (!done) {
    if (bp->total_length > 0 && bp->count > 0 && dl_total_time > 3) {
      int eta;

      if (bp->total_length != size && bp->last_eta_value != 0 && dl_total_time - bp->last_eta_time < ETA_REFRESH_INTERVAL)
        eta = bp->last_eta_value;
      else {
        wgint bytes_remaining = bp->total_length - size;
        double eta_ = dl_total_time * bytes_remaining / bp->count;
        if (eta_ >= INT_MAX - 1)
          goto skip_eta;
        eta = (int)(eta_ + 0.5);
        bp->last_eta_value = eta;
        bp->last_eta_time = dl_total_time;
      }

      p += sprintf(p, get_eta(&bytes_cols_diff), eta_to_human_short(eta, false));
    }
    else if (bp->total_length > 0) {
    skip_eta:
      memset(p, ' ', PROGRESS_ETA_LEN);
      p += PROGRESS_ETA_LEN;
    }
  }
  else {
    int nbytes;
    int ncols;

    strcpy(p, _("    in "));
    nbytes = (int)strlen(p);
    ncols = count_cols(p);
    bytes_cols_diff = nbytes - ncols;
    if (dl_total_time >= 10)
      ncols += sprintf(p + nbytes, "%s", eta_to_human_short((int)(dl_total_time + 0.5), false));
    else
      ncols += sprintf(p + nbytes, "%ss", print_decimal(dl_total_time));
    p += ncols + bytes_cols_diff;
    if (ncols < PROGRESS_ETA_LEN) {
      memset(p, ' ', (size_t)(PROGRESS_ETA_LEN - ncols));
      p += PROGRESS_ETA_LEN - ncols;
    }
  }

  *p = '\0';

  padding = bp->width - count_cols(bp->buffer);
  assert(padding >= 0 && "Padding length became non-positive");
  if (padding > 0) {
    memset(p, ' ', (size_t)padding);
    p += padding;
    *p = '\0';
  }

  assert(count_cols(bp->buffer) == bp->width);
}

/* print buffer as a carriage-returned one-line image */

static void display_image(char* buf) {
  bool old = log_set_save_context(false);
  logputs(LOG_PROGRESS, "\r");
  logputs(LOG_PROGRESS, buf);
  log_set_save_context(old);
}

/* Modern bar behavior for Unix/Linux
 * disable interactivity if OpenSSL is running with alarm-based timeouts
 */

static void bar_set_params(const char* params) {
#if defined(HAVE_LIBSSL) && defined(OPENSSL_RUN_WITHTIMEOUT)
  current_impl->interactive = false;
#else
  current_impl->interactive = true;
#endif

  if (params) {
    for (const char* param = params; *param;) {
      if (!strncmp(param, "force", 5))
        current_impl_locked = 1;
      else if (!strncmp(param, "noscroll", 8))
        opt.noscroll = true;

      if (*(param = strchrnul(param, ':')))
        param++;
    }
  }

  if (((opt.lfilename && opt.show_progress != 1)
#ifdef HAVE_ISATTY
       || !isatty(fileno(stderr))
#endif
           ) &&
      !current_impl_locked) {
    set_progress_implementation(FALLBACK_PROGRESS_IMPLEMENTATION);
    return;
  }
}

#ifdef SIGWINCH
void progress_handle_sigwinch(int sig WGET_ATTR_UNUSED) {
  received_sigwinch = 1;
  signal(SIGWINCH, progress_handle_sigwinch);
}
#endif

/* Compact human-readable ETA formatter
 * uses at most 7 screen columns
 */

static const char* eta_to_human_short(int secs, bool condensed) {
  static char buf[16];
  static int last = -1;
  const char* space = condensed ? "" : " ";

  if (secs == last)
    return buf;
  last = secs;

  if (secs < 100)
    sprintf(buf, "%ds", secs);
  else if (secs < 100 * 60)
    sprintf(buf, "%dm%s%ds", secs / 60, space, secs % 60);
  else if (secs < 48 * 3600)
    sprintf(buf, "%dh%s%dm", secs / 3600, space, (secs / 60) % 60);
  else if (secs < 100 * 86400)
    sprintf(buf, "%dd%s%dh", secs / 86400, space, (secs / 3600) % 24);
  else
    sprintf(buf, "%dd", secs / 86400);

  return buf;
}
