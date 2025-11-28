/* Download progress
 * src/progress.c
 */

#include "wget.h"

#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ev.h>

#include "c-strcase.h"
#include "progress.h"
#include "retr.h"
#include "utils.h"

struct progress_implementation {
  const char* name;
  bool interactive;
  void* (*create)(const char*, wgint, wgint);
  void (*update)(void*, wgint, double);
  void (*draw)(void*);
  void (*finish)(void*, double);
  void (*set_params)(const char*);
};

/* Necessary forward declarations */

static void* dot_create(const char*, wgint, wgint);
static void dot_update(void*, wgint, double);
static void dot_finish(void*, double);
static void dot_draw(void*);
static void dot_set_params(const char*);

static void* bar_create(const char*, wgint, wgint);
static void bar_update(void*, wgint, double);
static void bar_draw(void*);
static void bar_finish(void*, double);
static void bar_set_params(const char*);

/* libev integration */

static struct ev_loop* progress_loop;
static ev_timer progress_timer;
static ev_signal sigwinch_watcher;

/* there is still a single active progress object, same as classic wget */
static void* current_progress;

static void progress_tick_cb(EV_P_ ev_timer* w, int revents);
static void progress_sigwinch_cb(EV_P_ ev_signal* w, int revents);

/* Progress implementations */

static struct progress_implementation implementations[] = {
    {"dot", 0, dot_create, dot_update, dot_draw, dot_finish, dot_set_params},
    {"bar", 1, bar_create, bar_update, bar_draw, bar_finish, bar_set_params},
};

static struct progress_implementation* current_impl;
static int current_impl_locked;

static volatile sig_atomic_t output_redirected;
static volatile sig_atomic_t received_sigwinch;

/* Progress implementation used by default
   Can be overridden in wgetrc or by the fallback one
 */

#define DEFAULT_PROGRESS_IMPLEMENTATION "bar"

/* Fallback progress implementation should be something that works
   under all display types
   If you put something other than "dot" here, remember that
   bar_set_params tries to switch to this if we're not running on a TTY
 */

#define FALLBACK_PROGRESS_IMPLEMENTATION "dot"

/* Return true if NAME names a valid progress bar implementation
   The characters after the first : will be ignored
 */

bool valid_progress_implementation_p(const char* name) {
  size_t i;
  struct progress_implementation* pi = implementations;
  char* colon = strchr(name, ':');
  size_t namelen = colon ? (size_t)(colon - name) : strlen(name);

  for (i = 0; i < countof(implementations); i++, pi++)
    if (!strncmp(pi->name, name, namelen))
      return true;
  return false;
}

/* Set the progress implementation to NAME */

void set_progress_implementation(const char* name) {
  size_t i, namelen;
  struct progress_implementation* pi = implementations;
  const char* colon;

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

      return;
    }
  }

  /* fallback instead of hard abort, keeps async daemon use safer */
  current_impl = &implementations[0];
  current_impl_locked = 0;
  if (current_impl->set_params)
    current_impl->set_params(NULL);
}

/* libev driven periodic redraw
   called from the event loop thread only */

static void progress_tick_cb(EV_P_ ev_timer* w, int revents) {
  (void)w;
  (void)revents;

  if (!current_impl || !current_progress)
    return;

  if (!current_impl->interactive)
    return;

  current_impl->draw(current_progress);
}

/* SIGWINCH from libev signal watcher */

static void progress_sigwinch_cb(EV_P_ ev_signal* w, int revents) {
  (void)w;
  (void)revents;
  received_sigwinch = 1;
}

/* external init/shutdown to hook into libev loop */

void progress_init(struct ev_loop* loop) {
  progress_loop = loop;

  /* tick every 200ms which matches the old REFRESH_INTERVAL */
  ev_timer_init(&progress_timer, progress_tick_cb, 0.2, 0.2);
  ev_timer_start(progress_loop, &progress_timer);

#ifdef SIGWINCH
  ev_signal_init(&sigwinch_watcher, progress_sigwinch_cb, SIGWINCH);
  ev_signal_start(progress_loop, &sigwinch_watcher);
#endif
}

void progress_shutdown(void) {
  if (!progress_loop)
    return;

  ev_timer_stop(progress_loop, &progress_timer);
#ifdef SIGWINCH
  ev_signal_stop(progress_loop, &sigwinch_watcher);
#endif
  progress_loop = NULL;
}

/* Redirect handling from logging subsystem */

void progress_schedule_redirect(void) {
  output_redirected = 1;
}

/* Create a progress gauge
   INITIAL is the number of bytes the download starts from (zero if the download starts from scratch)
   TOTAL is the expected total number of bytes in this download
   If TOTAL is zero, it means that the download size is not known in advance
 */

void* progress_create(const char* f_download, wgint initial, wgint total) {
  void* progress;

  /* Check if the log status has changed under our feet */
  if (output_redirected) {
    if (!current_impl_locked)
      set_progress_implementation(FALLBACK_PROGRESS_IMPLEMENTATION);
    output_redirected = 0;
  }

  if (!current_impl)
    set_progress_implementation(NULL);

  progress = current_impl->create(f_download, initial, total);
  current_progress = progress;
  return progress;
}

/* Return true if the progress gauge is "interactive", i.e. if it can
   profit from being called regularly even in absence of data
 */

bool progress_interactive_p(void* progress WGET_ATTR_UNUSED) {
  bool interactive = false;

  if (current_impl)
    interactive = current_impl->interactive;

  return interactive;
}

/* Inform the progress gauge of newly received bytes
   DLTIME is the time since the beginning of the download
 */

void progress_update(void* progress, wgint howmuch, double dltime) {
  /* sanitize input */
  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;

  if (howmuch < 0)
    howmuch = 0;

  if (!current_impl || !progress)
    return;

  /* async friendly, no drawing here */
  current_impl->update(progress, howmuch, dltime);
}

/* Tell the progress gauge to clean up
   Calling this will free the PROGRESS object, the further use of which is not allowed
 */

void progress_finish(void* progress, double dltime) {
  /* sanitize input */
  if (dltime >= INT_MAX)
    dltime = INT_MAX - 1;
  else if (dltime < 0)
    dltime = 0;

  if (!current_impl || !progress)
    return;

  current_impl->finish(progress, dltime);

  if (progress == current_progress)
    current_progress = NULL;
}

/* Dot-printing */

struct dot_progress {
  wgint initial_length; /* how many bytes have been downloaded previously */
  wgint total_length;   /* expected total byte count when the download finishes */

  wgint accumulated; /* number of bytes accumulated after the last printed dot */

  double dltime; /* download time so far */
  wgint rows;    /* number of rows printed so far */
  int dots;      /* number of dots printed in this row */

  double last_timer_value;
};

/* Dot-progress backend for progress_create */

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

      /* Align the [ skipping ... ] line with the dots */
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

static const char* eta_to_human_short(int, bool);

/* ADD_DOT_ROWS_THRS - minimal (1 << ADD_DOT_ROWS_THRS) ROWS to be added
   to the current row if dp->accumulated too much
   Allows to reduce dot_draw IO and log traffic
 */

#ifndef ADD_DOT_ROWS_THRS
#define ADD_DOT_ROWS_THRS 2
#endif /* ADD_DOT_ROWS_THRS */

/* Prints the stats (percentage of completion, speed, ETA) for current row
   DLTIME is the time spent downloading the data in current row
 */

static void
#if ADD_DOT_ROWS_THRS
print_row_stats(struct dot_progress* dp, double dltime, bool last, wgint added_rows)
#else
print_row_stats(struct dot_progress* dp, double dltime, bool last)
#endif
{
  const wgint ROW_BYTES = opt.dot_bytes * opt.dots_in_line;

  /* bytes_displayed is the number of bytes indicated to the user by
     dots printed so far, includes the initially "skipped" amount */
  wgint bytes_displayed = dp->rows * ROW_BYTES + dp->dots * opt.dot_bytes;

  if (last)
    bytes_displayed += dp->accumulated;

  if (bytes_displayed < 0)
    bytes_displayed = 0;

  if (dp->total_length) {
    /* Round to floor value to provide gauge how much data has been retrieved
       12.8% will round to 12% because the 13% mark has not yet been reached
       100% is only shown when done */
    int percentage = 100.0 * bytes_displayed / dp->total_length;
    logprintf(LOG_PROGRESS, "%3d%%", percentage);
  }

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

/* Dot-progress backend for progress_update */

static void dot_update(void* progress, wgint howmuch, double dltime) {
  /* sanitize input */
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
#endif /* ADD_DOT_ROWS_THRS */
    }
  }

  log_set_flush(true);
}

/* Dot-progress backend for progress_finish */

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

  /* sanitize input */
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
  log_set_flush(false);

  xfree(dp);
}

/* This function interprets the progress "parameters"
   For example, if Wget is invoked with --progress=dot:mega, it will set the
   "dot-style" to "mega"
   Valid styles are default, binary, mega, and giga
 */

static void dot_set_params(const char* params) {
  current_impl->interactive = false;
  if (!params || !*params)
    params = opt.dot_style;

  if (!params)
    return;

  if (!c_strcasecmp(params, "default")) {
    /* Default style: 1K dots, 10 dots in a cluster, 50 dots in a line */
    opt.dot_bytes = 1024;
    opt.dot_spacing = 10;
    opt.dots_in_line = 50;
  }
  else if (!c_strcasecmp(params, "binary")) {
    /* "Binary" retrieval: 8K dots, 16 dots in a cluster, 48 dots in a line */
    opt.dot_bytes = 8192;
    opt.dot_spacing = 16;
    opt.dots_in_line = 48;
  }
  else if (!c_strcasecmp(params, "mega")) {
    /* "Mega" retrieval: each dot is 64K, 8 dots in a cluster, 6 clusters (3M) in a line */
    opt.dot_bytes = 65536L;
    opt.dot_spacing = 8;
    opt.dots_in_line = 48;
  }
  else if (!c_strcasecmp(params, "giga")) {
    /* "Giga" retrieval: each dot is 1M, 8 dots in a cluster, 4 clusters (32M) in a line */
    opt.dot_bytes = (1L << 20);
    opt.dot_spacing = 8;
    opt.dots_in_line = 32;
  }
  else
    fprintf(stderr, _("Invalid dot style specification %s; leaving unchanged.\n"), quote(params));
}

/* "Thermometer" (bar) progress */

/* Assumed screen width if we can't find the real value */
#define DEFAULT_SCREEN_WIDTH 80

/* Minimum screen width we'll try to work with
   If this is too small, the progress layout would get cramped */
#define MINIMUM_SCREEN_WIDTH 51

static int screen_width;

/* Size of the download speed history ring */

#define DLSPEED_HISTORY_SIZE 20

#define DLSPEED_SAMPLE_MIN 0.15
#define STALL_START_TIME 5
#define REFRESH_INTERVAL 0.2
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

static void create_image(struct bar_progress*, double, bool);
static void display_image(char*);
static void update_speed_ring(struct bar_progress*, wgint, double);

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

/* helper to truncate long filenames with .. in the middle to fit width chars */

static void format_filename_middle(char* dst, size_t width, const char* src) {
  size_t len = strlen(src);

  if (width == 0) {
    dst[0] = '\0';
    return;
  }

  if (len <= width) {
    memcpy(dst, src, len);
    if (len < width)
      memset(dst + len, ' ', width - len);
    dst[width] = '\0';
    return;
  }

  if (width <= 2) {
    memset(dst, '.', width);
    dst[width] = '\0';
    return;
  }

  size_t keep = width - 2;
  size_t head = keep * 2 / 3;
  size_t tail = keep - head;

  memcpy(dst, src, head);
  dst[head] = '.';
  dst[head + 1] = '.';
  memcpy(dst + head + 2, src + len - tail, tail);
  dst[width] = '\0';
}

/* optional ANSI coloring for the bar on modern terminals */

static bool progress_use_color(void) {
  static int cached = -1;

  if (cached != -1)
    return cached;

  if (!isatty(fileno(stderr))) {
    cached = 0;
    return false;
  }

  if (getenv("NO_COLOR")) {
    cached = 0;
    return false;
  }

  cached = 1;
  return true;
}

#define C_RESET "\033[0m"
#define C_CYAN "\033[36m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"

static void* bar_create(const char* f_download, wgint initial, wgint total) {
  struct bar_progress* bp = xnew0(struct bar_progress);

  if (initial > total)
    total = initial;

  bp->initial_length = initial;
  bp->total_length = total;

  bp->f_download = xmalloc(prepare_filename(NULL, f_download));
  prepare_filename(bp->f_download, f_download);

  if (!screen_width || received_sigwinch) {
    screen_width = determine_screen_width();
    if (!screen_width)
      screen_width = DEFAULT_SCREEN_WIDTH;
    else if (screen_width < MINIMUM_SCREEN_WIDTH)
      screen_width = MINIMUM_SCREEN_WIDTH;
    received_sigwinch = 0;
  }

  bp->width = screen_width - 1;

#define BUF_LEN (bp->width * 2 + 100)
  bp->buffer = xcalloc(BUF_LEN, 1);

  /* no initial draw here, wait until we have some data */

  return bp;
}

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

  /* do not bother drawing before we have any data or time */
  if (bp->count == 0 && !force_screen_update)
    return;

  if (bp->dltime - bp->last_screen_update < REFRESH_INTERVAL && !force_screen_update)
    return;

  create_image(bp, bp->dltime, false);
  display_image(bp->buffer);
  bp->last_screen_update = bp->dltime;
}

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

/* maintain current download speed over a sliding window */

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

/* build a single human friendly progress line */

static void create_image(struct bar_progress* bp, double dl_total_time, bool done) {
  char* buf = bp->buffer;
  char* p = buf;

  wgint size = bp->initial_length + bp->count;
  struct bar_progress_hist* hist = &bp->hist;

  if (dl_total_time >= INT_MAX)
    dl_total_time = INT_MAX - 1;
  else if (dl_total_time < 0)
    dl_total_time = 0;

  const int term_width = bp->width > 60 ? bp->width : 60;

  const int file_col_width = 28;
  const int bar_width = 24;

  char fname[file_col_width + 1];
  format_filename_middle(fname, file_col_width, bp->f_download);

  p += sprintf(p, "%-*s  ", file_col_width, fname);

  char size_buf[32];
  char total_buf[32];

  const char* hs = human_readable(size, 1000, 2);
  snprintf(size_buf, sizeof(size_buf), "%s", hs);

  if (bp->total_length > 0) {
    const char* ht = human_readable(bp->total_length, 1000, 2);
    snprintf(total_buf, sizeof(total_buf), "%s", ht);
    p += sprintf(p, "%7s/%-7s  ", size_buf, total_buf);
  }
  else {
    p += sprintf(p, "%7s        ", size_buf);
    *p++ = ' ';
    *p++ = ' ';
  }

  bool use_color = progress_use_color();
  double frac = 0.0;
  if (bp->total_length > 0)
    frac = (double)size / (double)bp->total_length;
  if (frac < 0.0)
    frac = 0.0;
  if (frac > 1.0)
    frac = 1.0;

  int filled = (int)(frac * bar_width + 0.5);
  if (filled > bar_width)
    filled = bar_width;

  if (!done && bp->total_length <= 0) {
    int pos = bp->tick % bar_width;

    if (use_color)
      p += sprintf(p, "%s[", C_CYAN);
    else
      *p++ = '[';

    for (int i = 0; i < bar_width; i++) {
      if (i == pos)
        *p++ = '>';
      else
        *p++ = ' ';
    }

    if (use_color) {
      *p++ = ']';
      p += sprintf(p, "%s", C_RESET);
    }
    else {
      *p++ = ']';
    }
  }
  else {
    const char* bar_color = C_CYAN;
    if (done)
      bar_color = C_GREEN;
    else if (bp->stalled)
      bar_color = C_YELLOW;

    if (use_color)
      p += sprintf(p, "%s[", bar_color);
    else
      *p++ = '[';

    for (int i = 0; i < bar_width; i++) {
      if (i < filled)
        *p++ = '=';
      else
        *p++ = ' ';
    }

    if (use_color) {
      *p++ = ']';
      p += sprintf(p, "%s", C_RESET);
    }
    else {
      *p++ = ']';
    }
  }

  *p++ = ' ';
  *p++ = ' ';

  if (bp->total_length > 0) {
    int percentage = 100.0 * size / bp->total_length;
    if (percentage < 0)
      percentage = 0;
    if (percentage > 100)
      percentage = 100;
    p += sprintf(p, "%3d%%  ", percentage);
  }
  else {
    p += sprintf(p, "     ");
  }

  if (hist->total_time > 0 && hist->total_bytes) {
    static const char* short_units[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
    static const char* short_units_bits[] = {"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"};
    int units = 0;
    wgint dlquant = hist->total_bytes + bp->recent_bytes;
    double dltime = hist->total_time + (dl_total_time - bp->recent_start);
    double dlspeed = calc_rate(dlquant, dltime, &units);

    const char* unit_str = !opt.report_bps ? short_units[units] : short_units_bits[units];

    p += sprintf(p, "%4.*f%s  ", dlspeed >= 99.95 ? 0 : dlspeed >= 9.995 ? 1 : 2, dlspeed, unit_str);
  }
  else {
    p += sprintf(p, "  --.-KB/s  ");
  }

  if (!done) {
    if (bp->total_length > 0 && bp->count > 0 && dl_total_time > 1.0) {
      int eta;

      if (bp->total_length != size && bp->last_eta_value != 0 && dl_total_time - bp->last_eta_time < ETA_REFRESH_INTERVAL) {
        eta = bp->last_eta_value;
      }
      else {
        wgint bytes_remaining = bp->total_length - size;
        double eta_ = dl_total_time * bytes_remaining / bp->count;
        if (eta_ >= INT_MAX - 1)
          eta_ = INT_MAX - 1;
        if (eta_ < 0)
          eta_ = 0;
        eta = (int)(eta_ + 0.5);
        bp->last_eta_value = eta;
        bp->last_eta_time = dl_total_time;
      }

      p += sprintf(p, "%s", eta_to_human_short(eta, true));
    }
    else if (bp->total_length > 0) {
      p += sprintf(p, "  --");
    }
  }
  else {
    if (dl_total_time >= 10)
      p += sprintf(p, "%s", eta_to_human_short((int)(dl_total_time + 0.5), true));
    else
      p += sprintf(p, "%ss", print_decimal(dl_total_time));
  }

  *p = '\0';
  bp->tick++;
}

static void display_image(char* buf) {
  bool old = log_set_save_context(false);

  /* move to column 0 and clear whole line */
  logputs(LOG_PROGRESS, "\r\033[2K");
  logputs(LOG_PROGRESS, buf);

  log_set_save_context(old);
}

/* Modern Linux/Unix bar behavior
   Disable interactive bar with OpenSSL timeouts when needed
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

  if (((opt.lfilename && opt.show_progress != 1) || !isatty(fileno(stderr))) && !current_impl_locked) {
    struct progress_implementation* fallback = NULL;

    for (size_t i = 0; i < countof(implementations); i++) {
      if (!strcmp(implementations[i].name, FALLBACK_PROGRESS_IMPLEMENTATION)) {
        fallback = &implementations[i];
        break;
      }
    }

    if (fallback) {
      current_impl = fallback;
      current_impl_locked = 0;
      if (current_impl->set_params)
        current_impl->set_params(NULL);
    }

    return;
  }
}

/* legacy entry point kept for compatibility
   in the async build, SIGWINCH is driven via libev and this simply marks the flag */

void progress_handle_sigwinch(int sig WGET_ATTR_UNUSED) {
  (void)sig;
  received_sigwinch = 1;
}

/* Provide a short human-readable rendition of the ETA
   Display never occupies more than 7 characters of screen space
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
