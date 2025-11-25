/* Messages logging
 * src/log.c
 */

#include "wget.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "utils.h"
#include "exits.h"
#include "log.h"
#include "threading.h"

/* This file implements support for logging
   Logging means printing output with additional features:

   - Categorizing output by importance
   - Redirecting output to a log file on demand or signal
   - Optionally keeping a small in-memory context buffer
 */

/* Logging destination
   Before log_init is called, logging goes to stderr
   After log_init, logging goes to logfp unless inhibited */
static FILE* logfp;

/* Descriptor of the stdout|stderr */
static FILE* stdlogfp;

/* Descriptor of the wget.log* file (if created) */
static FILE* filelogfp;

/* Name of log file */
static char* logfile;

/* Is interactive shell */
static int shell_is_interactive;

/* Secondary log (used by WARC writer when enabled) */
static FILE* warclogfp;

/* If true, logging is inhibited and nothing is printed or stored */
static bool inhibit_logging;

/* Whether to store recent lines for context dumping */
static bool save_context_p;

/* Whether the log is flushed after each message */
static bool flush_log_p = true;

/* Whether output arrived while flushing was disabled */
static bool needs_flushing;

/* Number of lines kept as context when redirecting output */
#define SAVED_LOG_LINES 24

/* See comment above: a small circular buffer of recent log lines */
#define STATIC_LENGTH 128

static struct log_ln {
  char static_line[STATIC_LENGTH + 1]; /* inline storage for short lines */
  char* malloced_line;                 /* heap storage for longer lines */
  char* content;                       /* points to static_line or malloced_line */
} log_lines[SAVED_LOG_LINES];

/* Current position in the ring buffer, -1 when empty */
static int log_line_current = -1;

/* Whether the last written line did not end with '\n' */
static bool trailing_line;

static void check_redirect_output_locked(void);
static void redirect_output_locked(bool, const char*);
static void logflush_locked(void);

static wget_mutex_t log_mutex;

static void log_lock(void) {
  static bool initialized = false;
  if (!initialized) {
    wget_mutex_init(&log_mutex);
    initialized = true;
  }
  wget_mutex_lock(&log_mutex);
}

static void log_unlock(void) {
  wget_mutex_unlock(&log_mutex);
}

#define ROT_ADVANCE(num)          \
  do {                            \
    if (++num >= SAVED_LOG_LINES) \
      num = 0;                    \
  } while (0)

/* Free the log line at index NUM
   Frees malloced_line if needed and clears content */
static void free_log_line(int num) {
  struct log_ln* ln = log_lines + num;
  xfree(ln->malloced_line);
  ln->content = NULL;
}

/* Append bytes in the range [start, end) to one line in the log
   The region is not supposed to contain newlines except possibly
   for end[-1] */
static void saved_append_1(const char* start, const char* end) {
  int len = end - start;
  if (!len)
    return;

  /* Create a new line or append to the trailing one */
  if (!trailing_line) {
    struct log_ln* ln;

    if (log_line_current == -1)
      log_line_current = 0;
    else
      free_log_line(log_line_current);

    ln = log_lines + log_line_current;
    if (len > STATIC_LENGTH) {
      ln->malloced_line = strdupdelim(start, end);
      ln->content = ln->malloced_line;
    }
    else {
      memcpy(ln->static_line, start, len);
      ln->static_line[len] = '\0';
      ln->content = ln->static_line;
    }
  }
  else {
    /* Append to the last line */
    struct log_ln* ln = log_lines + log_line_current;

    if (ln->malloced_line) {
      int old_len = strlen(ln->malloced_line);
      ln->malloced_line = xrealloc(ln->malloced_line, old_len + len + 1);
      memcpy(ln->malloced_line + old_len, start, len);
      ln->malloced_line[old_len + len] = '\0';
      ln->content = ln->malloced_line;
    }
    else {
      int old_len = strlen(ln->static_line);
      if (old_len + len > STATIC_LENGTH) {
        ln->malloced_line = xmalloc(old_len + len + 1);
        memcpy(ln->malloced_line, ln->static_line, old_len);
        memcpy(ln->malloced_line + old_len, start, len);
        ln->malloced_line[old_len + len] = '\0';
        ln->content = ln->malloced_line;
      }
      else {
        memcpy(ln->static_line + old_len, start, len);
        ln->static_line[old_len + len] = '\0';
        ln->content = ln->static_line;
      }
    }
  }

  trailing_line = (end[-1] != '\n');
  if (!trailing_line)
    ROT_ADVANCE(log_line_current);
}

/* Log the contents of S into the context ring buffer
   Multiple lines are tracked separately
   Trailing partial lines are merged with the next write */
static void saved_append(const char* s) {
  while (*s) {
    const char* end = strchr(s, '\n');
    if (!end)
      end = s + strlen(s);
    else
      ++end;
    saved_append_1(s, end);
    s = end;
  }
}

/* Check X against opt.verbose and opt.quiet */

#define CHECK_VERBOSE(x)            \
  switch (x) {                      \
    case LOG_PROGRESS:              \
      if (!opt.show_progress)       \
        return;                     \
      break;                        \
    case LOG_ALWAYS:                \
      break;                        \
    case LOG_NOTQUIET:              \
      if (opt.quiet)                \
        return;                     \
      break;                        \
    case LOG_NONVERBOSE:            \
      if (opt.verbose || opt.quiet) \
        return;                     \
      break;                        \
    case LOG_VERBOSE:               \
      if (!opt.verbose)             \
        return;                     \
  }

/* Return the FILE* used for logging
   Before log_init: stderr
   If logging is inhibited: NULL */
static FILE* get_log_fp(void) {
  if (inhibit_logging)
    return NULL;
  if (logfp)
    return logfp;
  return stderr;
}

/* Return the FILE* used for progress output */
static FILE* get_progress_fp(void) {
  if (opt.show_progress)
    return stderr;
  return get_log_fp();
}

/* Return the FILE* used for the secondary log
   If WARC logging is disabled and no primary log exists, fall back to stderr
   If logging is inhibited: NULL */
static FILE* get_warc_log_fp(void) {
  if (inhibit_logging)
    return NULL;
  if (warclogfp)
    return warclogfp;
  if (logfp)
    return NULL;
  return stderr;
}

/* Set the secondary log file pointer */
void log_set_warc_log_fp(FILE* fp) {
  log_lock();
  warclogfp = fp;
  log_unlock();
}

/* Log a literal string S without appending a newline */
void logputs(enum log_options o, const char* s) {
  FILE* fp;
  FILE* warcfp;
  int errno_save = errno;

  CHECK_VERBOSE(o);

  log_lock();

  check_redirect_output_locked();
  errno = errno_save;

  if (o == LOG_PROGRESS)
    fp = get_progress_fp();
  else
    fp = get_log_fp();

  errno = errno_save;

  if (fp == NULL) {
    log_unlock();
    return;
  }

  warcfp = get_warc_log_fp();
  errno = errno_save;

  fputs(s, fp);
  if (warcfp != NULL)
    fputs(s, warcfp);

  if (save_context_p)
    saved_append(s);

  if (flush_log_p)
    logflush_locked();
  else
    needs_flushing = true;

  errno = errno_save;
  log_unlock();
}

struct logvprintf_state {
  char* bigmsg;
  int expected_size;
  int allocated;
};

/* Core printf-style logging backend using vsnprintf
   Keeps optional in-memory context and mirrors to warclog when active */
static bool GCC_FORMAT_ATTR(2, 0) log_vprintf_internal(struct logvprintf_state* state, const char* fmt, va_list args) {
  char smallmsg[128];
  char* write_ptr = smallmsg;
  int available_size = sizeof(smallmsg);
  int numwritten;
  FILE* fp = get_log_fp();
  FILE* warcfp = get_warc_log_fp();

  if (fp == NULL)
    return false;

  if (!save_context_p && warcfp == NULL) {
    /* Fast path when we do not need buffering or duplication */
    vfprintf(fp, fmt, args);
    goto flush;
  }

  if (state->allocated != 0) {
    write_ptr = state->bigmsg;
    available_size = state->allocated;
  }

  numwritten = vsnprintf(write_ptr, available_size, fmt, args);

  if (numwritten == -1) {
    int newsize = available_size << 1;
    state->bigmsg = xrealloc(state->bigmsg, newsize);
    state->allocated = newsize;
    return false;
  }
  else if (numwritten >= available_size) {
    int newsize = numwritten + 1;
    state->bigmsg = xrealloc(state->bigmsg, newsize);
    state->allocated = newsize;
    return false;
  }

  if (save_context_p)
    saved_append(write_ptr);

  fputs(write_ptr, fp);
  if (warcfp != NULL && warcfp != fp)
    fputs(write_ptr, warcfp);

  xfree(state->bigmsg);

flush:
  if (flush_log_p)
    logflush_locked();
  else
    needs_flushing = true;

  return true;
}

/* Flush logfp and warclogfp when active */
static void logflush_locked(void) {
  FILE* fp = get_log_fp();
  FILE* warcfp = get_warc_log_fp();

  if (fp)
    fflush(fp);
  if (warcfp)
    fflush(warcfp);

  needs_flushing = false;
}

void logflush(void) {
  log_lock();
  logflush_locked();
  log_unlock();
}

/* Enable or disable log flushing */
void log_set_flush(bool flush) {
  log_lock();
  if (flush == flush_log_p) {
    log_unlock();
    return;
  }

  if (!flush) {
    flush_log_p = false;
  }
  else {
    if (needs_flushing)
      logflush_locked();
    flush_log_p = true;
  }

  log_unlock();
}

/* Enable/disable storing log context in memory
   Returns previous state so caller can restore it */
bool log_set_save_context(bool savep) {
  bool old;

  log_lock();
  old = save_context_p;
  save_context_p = savep;
  log_unlock();
  return old;
}

/* Print a formatted message to the log with verbosity control */
void logprintf(enum log_options o, const char* fmt, ...) {
  va_list args;
  struct logvprintf_state lpstate;
  bool done;
  int errno_saved = errno;

  CHECK_VERBOSE(o);

  log_lock();

  check_redirect_output_locked();
  errno = errno_saved;

  if (inhibit_logging) {
    log_unlock();
    return;
  }

  xzero(lpstate);
  errno = 0;
  do {
    va_start(args, fmt);
    done = log_vprintf_internal(&lpstate, fmt, args);
    va_end(args);

    if (done && errno == EPIPE) {
      log_unlock();
      exit(WGET_EXIT_GENERIC_ERROR);
    }
  } while (!done);

  errno = errno_saved;
  log_unlock();
}

#ifdef ENABLE_DEBUG
/* Same as logprintf but only active when opt.debug is true */
void debug_logprintf(const char* fmt, ...) {
  if (opt.debug) {
    va_list args;
    struct logvprintf_state lpstate;
    bool done;

    log_lock();
#ifndef TESTING
    check_redirect_output_locked();
#endif
    if (inhibit_logging) {
      log_unlock();
      return;
    }

    xzero(lpstate);
    do {
      va_start(args, fmt);
      done = log_vprintf_internal(&lpstate, fmt, args);
      va_end(args);
    } while (!done);

    log_unlock();
  }
}
#endif /* ENABLE_DEBUG */

/* Initialize logging
   If FILE is "-", log to stdout
   If FILE is NULL, log to stderr and optionally enable context capture */
void log_init(const char* file, bool appendp) {
  log_lock();

  if (file) {
    if (HYPHENP(file)) {
      stdlogfp = stdout;
      logfp = stdlogfp;
    }
    else {
      filelogfp = fopen(file, appendp ? "a" : "w");
      if (!filelogfp) {
        fprintf(stderr, "%s: %s: %s\n", exec_name, file, strerror(errno));
        exit(WGET_EXIT_GENERIC_ERROR);
      }
      logfp = filelogfp;
    }
  }
  else {
    /* Default to stderr to avoid colliding with -O - output */
    stdlogfp = stderr;
    logfp = stdlogfp;

#ifdef HAVE_ISATTY
    if (isatty(fileno(logfp)))
      save_context_p = true;
#endif
  }

  /* Snapshot whether stdin is interactive once at startup */
  shell_is_interactive = isatty(STDIN_FILENO);

  log_unlock();
}

/* Close primary log stream and drop in-memory context */
void log_close(void) {
  int i;

  log_lock();

  if (logfp && logfp != stderr && logfp != stdout) {
    if (logfp == stdlogfp)
      stdlogfp = NULL;
    if (logfp == filelogfp)
      filelogfp = NULL;
    fclose(logfp);
  }
  logfp = NULL;

  inhibit_logging = true;
  save_context_p = false;

  for (i = 0; i < SAVED_LOG_LINES; i++)
    free_log_line(i);
  log_line_current = -1;
  trailing_line = false;

  log_unlock();
}

/* Dump saved in-memory context lines to the current log destination */
static void log_dump_context(void) {
  int num = log_line_current;
  FILE* fp = get_log_fp();
  FILE* warcfp = get_warc_log_fp();

  if (!fp)
    return;
  if (num == -1)
    return;

  if (trailing_line)
    ROT_ADVANCE(num);

  do {
    struct log_ln* ln = log_lines + num;
    if (ln->content) {
      fputs(ln->content, fp);
      if (warcfp != NULL)
        fputs(ln->content, warcfp);
    }
    ROT_ADVANCE(num);
  } while (num != log_line_current);

  if (trailing_line && log_lines[log_line_current].content) {
    fputs(log_lines[log_line_current].content, fp);
    if (warcfp != NULL)
      fputs(log_lines[log_line_current].content, warcfp);
  }

  fflush(fp);
  if (warcfp)
    fflush(warcfp);
}

/* String escape helpers */

/* Count non-printable characters in SOURCE using c-ctype predicate */
static int count_nonprint(const char* source) {
  const char* p;
  int cnt;

  for (p = source, cnt = 0; *p; p++)
    if (!c_isprint(*p))
      ++cnt;
  return cnt;
}

/* Copy SOURCE to DEST, escaping non-printable characters
   ESCAPE is the leading escape character
   BASE must be 8 (octal) or 16 (hex) */
static void copy_and_escape(const char* source, char* dest, char escape, int base) {
  const char* from = source;
  char* to = dest;
  unsigned char c;

  switch (base) {
    case 8:
      while ((c = *from++) != '\0') {
        if (c_isprint(c))
          *to++ = c;
        else {
          *to++ = escape;
          *to++ = '0' + (c >> 6);
          *to++ = '0' + ((c >> 3) & 7);
          *to++ = '0' + (c & 7);
        }
      }
      break;

    case 16:
      while ((c = *from++) != '\0') {
        if (c_isprint(c))
          *to++ = c;
        else {
          *to++ = escape;
          *to++ = XNUM_TO_DIGIT(c >> 4);
          *to++ = XNUM_TO_DIGIT(c & 0xf);
        }
      }
      break;

    default:
      abort();
  }

  *to = '\0';
}

#define RING_SIZE 3
struct ringel {
  char* buffer;
  int size;
};
static struct ringel ring[RING_SIZE];

/* Worker for escnonprint / escnonprint_uri
   Keeps a small ring of static buffers to be printf-friendly */
static const char* escnonprint_internal(const char* str, char escape, int base) {
  static int ringpos;
  int nprcnt;

  assert(base == 8 || base == 16);

  nprcnt = count_nonprint(str);
  if (nprcnt == 0)
    return str;

  {
    struct ringel* r = ring + ringpos;
    int needed_size = strlen(str) + 1 + (base == 8 ? 3 * nprcnt : 2 * nprcnt);

    if (r->buffer == NULL || r->size < needed_size) {
      r->buffer = xrealloc(r->buffer, needed_size);
      r->size = needed_size;
    }

    copy_and_escape(str, r->buffer, escape, base);
    ringpos = (ringpos + 1) % RING_SIZE;
    return r->buffer;
  }
}

/* Escape non-printable characters as \ooo */
const char* escnonprint(const char* str) {
  return escnonprint_internal(str, '\\', 8);
}

/* Escape non-printable characters as %XX (URI style) */
const char* escnonprint_uri(const char* str) {
  return escnonprint_internal(str, '%', 16);
}

#if defined DEBUG_MALLOC || defined TESTING
void log_cleanup(void) {
  size_t i;
  log_lock();
  for (i = 0; i < countof(ring); i++)
    xfree(ring[i].buffer);
  log_unlock();
}
#endif

/* When SIGHUP or SIGUSR1 are received, output is redirected
   Such signal-requested redirection is treated as permanent */
static const char* redirect_request_signal_name;

/* Redirect output to a log file or back to stdout/stderr */
static void redirect_output_locked(bool to_file, const char* signal_name) {
  if (to_file && logfp != filelogfp) {
    if (signal_name)
      fprintf(stderr, "\n%s received.", signal_name);

    if (!filelogfp) {
      filelogfp = unique_create(DEFAULT_LOGFILE, false, &logfile);
      if (filelogfp) {
        fprintf(stderr, _("\nRedirecting output to %s.\n"), quote(logfile));
        redirect_request_signal_name = signal_name;
        logfp = filelogfp;
        log_dump_context();
      }
      else {
        fprintf(stderr, _("%s: %s; disabling logging.\n"), logfile ? logfile : DEFAULT_LOGFILE, strerror(errno));
        inhibit_logging = true;
      }
    }
    else {
      fprintf(stderr, _("\nRedirecting output to %s.\n"), quote(logfile));
      logfp = filelogfp;
      log_dump_context();
    }
  }
  else if (!to_file && logfp != stdlogfp) {
    logfp = stdlogfp;
    log_dump_context();
  }
}

void redirect_output(bool to_file, const char* signal_name) {
  log_lock();
  redirect_output_locked(to_file, signal_name);
  log_unlock();
}

/* Check whether logging should be redirected
   If the shell is interactive and no explicit log file is in use,
   backgrounding the process causes redirection to a persistent log */
static void check_redirect_output_locked(void) {
  if (!redirect_request_signal_name && shell_is_interactive && !opt.lfilename) {
    pid_t foreground_pgrp = tcgetpgrp(STDIN_FILENO);

    if (foreground_pgrp != -1 && foreground_pgrp != getpgrp() && !opt.quiet) {
      /* Process backgrounded */
      redirect_output_locked(true, NULL);
    }
    else {
      /* Process foregrounded */
      redirect_output_locked(false, NULL);
    }
  }
}
