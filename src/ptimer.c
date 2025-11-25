/* Portable timers
 * src/ptimer.c
 */

/* This file implements "portable timers" (ptimers), objects that
   measure elapsed time using primitives appropriate for modern
   Unix-like systems

   Entry points:

     ptimer_new        -- creates a timer
     ptimer_reset      -- resets the timer's elapsed time to zero
     ptimer_measure    -- measure and return the time elapsed since
                          creation or last reset
     ptimer_read       -- reads the last measured elapsed value
     ptimer_destroy    -- destroy the timer
     ptimer_resolution -- returns the approximate timer granularity

   Timers measure time in seconds as doubles, carrying as much precision
   as the underlying system timer supports

   Example:

     struct ptimer *tmr = ptimer_new();
     while (...)
       ... loop ...
     double secs = ptimer_measure(tmr);
     printf("The loop took %.2fs\n", secs);
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "utils.h"
#include "ptimer.h"

/* Depending on the OS, one and only one of PTIMER_POSIX
   or PTIMER_GETTIMEOFDAY will be defined */

#undef PTIMER_POSIX
#undef PTIMER_GETTIMEOFDAY

#if defined(_POSIX_TIMERS) && (_POSIX_TIMERS - 0 > 0)
#define PTIMER_POSIX /* use POSIX timers (clock_gettime) */
#else
#define PTIMER_GETTIMEOFDAY /* use gettimeofday */
#endif

#ifdef PTIMER_POSIX
/* Elapsed time measurement using POSIX timers:
   system time is held in struct timespec, time is retrieved using
   clock_gettime, and resolution using clock_getres */

typedef struct timespec ptimer_system_time;

#define IMPL_init posix_init
#define IMPL_measure posix_measure
#define IMPL_diff posix_diff
#define IMPL_resolution posix_resolution

/* clock_id to use for POSIX clocks, prefers CLOCK_MONOTONIC */
static int posix_clock_id;

/* Resolution of the clock, initialized in posix_init */
static double posix_clock_resolution;

/* Decide which clock_id to use */

static void posix_init(void) {
#define NO_SYSCONF_CHECK -1
  /* Candidates in preference order */
  static const struct {
    int id;
    int sysconf_name;
  } clocks[] = {
#if defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
      {CLOCK_MONOTONIC, _SC_MONOTONIC_CLOCK},
#endif
#ifdef CLOCK_HIGHRES
      {CLOCK_HIGHRES, NO_SYSCONF_CHECK},
#endif
      {CLOCK_REALTIME, NO_SYSCONF_CHECK},
  };
  size_t i;

  /* Pick the first usable clock
     Usable means sysconf says it is supported (when applicable)
     and clock_getres succeeds with a nonzero resolution */
  for (i = 0; i < countof(clocks); i++) {
    struct timespec r;

    if (clocks[i].sysconf_name != NO_SYSCONF_CHECK) {
      if (sysconf(clocks[i].sysconf_name) < 0)
        continue; /* sysconf claims this clock is unavailable */
    }

    if (clock_getres(clocks[i].id, &r) < 0)
      continue;

    posix_clock_id = clocks[i].id;
    posix_clock_resolution = (double)r.tv_sec + r.tv_nsec / 1e9;

    /* Guard against nonsense from a broken clock_getres */
    if (posix_clock_resolution == 0)
      posix_clock_resolution = 1e-3;

    break;
  }

  if (i == countof(clocks)) {
    /* If no clock was found, fall back to CLOCK_REALTIME
       and assume a millisecond-ish resolution */
    logprintf(LOG_NOTQUIET, _("Cannot get REALTIME clock frequency: %s\n"), strerror(errno));
    posix_clock_id = CLOCK_REALTIME;
    posix_clock_resolution = 1e-3;
  }
}

static inline void posix_measure(ptimer_system_time* pst) {
  clock_gettime(posix_clock_id, pst);
}

static inline double posix_diff(ptimer_system_time* pst1, ptimer_system_time* pst2) {
  return ((pst1->tv_sec - pst2->tv_sec) + (pst1->tv_nsec - pst2->tv_nsec) / 1e9);
}

static inline double posix_resolution(void) {
  return posix_clock_resolution;
}
#endif /* PTIMER_POSIX */

#ifdef PTIMER_GETTIMEOFDAY
/* Elapsed time measurement using gettimeofday:
   system time is held in struct timeval, retrieved using gettimeofday,
   and resolution is approximated */

typedef struct timeval ptimer_system_time;

#define IMPL_measure gettimeofday_measure
#define IMPL_diff gettimeofday_diff
#define IMPL_resolution gettimeofday_resolution

static inline void gettimeofday_measure(ptimer_system_time* pst) {
  gettimeofday(pst, NULL);
}

static inline double gettimeofday_diff(ptimer_system_time* pst1, ptimer_system_time* pst2) {
  return ((pst1->tv_sec - pst2->tv_sec) + (pst1->tv_usec - pst2->tv_usec) / 1e6);
}

static inline double gettimeofday_resolution(void) {
  /* gettimeofday granularity varies, but on modern systems
     it is typically better than 1 ms
     assume 100 µs */
  return 0.0001;
}
#endif /* PTIMER_GETTIMEOFDAY */

/* The code below this point is independent of timer implementation */

struct ptimer {
  /* Start time, used as the reference point for elapsed time */
  ptimer_system_time start;

  /* Most recent elapsed time value from ptimer_measure */
  double elapsed_last;

  /* Offset between the true start of measurement and START
     used to compensate when clock skew is detected */
  double elapsed_pre_start;
};

/* Allocate a new timer and reset it */

struct ptimer* ptimer_new(void) {
  struct ptimer* pt = xnew0(struct ptimer);
#ifdef IMPL_init
  static bool init_done;
  if (!init_done) {
    init_done = true;
    IMPL_init();
  }
#endif
  ptimer_reset(pt);
  return pt;
}

/* Free the resources associated with the timer */

void ptimer_destroy(struct ptimer* pt) {
  xfree(pt);
}

/* Reset timer PT
   This establishes the starting point from which ptimer_measure()
   will return elapsed time in seconds */

void ptimer_reset(struct ptimer* pt) {
  IMPL_measure(&pt->start);
  pt->elapsed_last = 0;
  pt->elapsed_pre_start = 0;
}

/* Measure elapsed time since creation or last reset
   This updates internal state and returns the elapsed seconds
   Clock skew (time moving backwards) is detected and compensated */

double ptimer_measure(struct ptimer* pt) {
  ptimer_system_time now;
  double elapsed;

  IMPL_measure(&now);
  elapsed = pt->elapsed_pre_start + IMPL_diff(&now, &pt->start);

  /* Ideally we just return the difference between NOW and pt->start
     However, the system clock might be adjusted backwards, producing
     a smaller or even negative value compared to the last measurement
     Callers expect a monotonically nondecreasing timer

     If ELAPSED regresses, reset START to now and treat the previous
     measured value as an offset so that the external view still
     moves forward */

  if (elapsed < pt->elapsed_last) {
    pt->start = now;
    pt->elapsed_pre_start = pt->elapsed_last;
    elapsed = pt->elapsed_last;
  }

  pt->elapsed_last = elapsed;
  return elapsed;
}

/* Return the most recent elapsed time measured with ptimer_measure
   Returns 0 if ptimer_measure has not yet been called */

double ptimer_read(const struct ptimer* pt) {
  return pt->elapsed_last;
}

/* Return the assessed resolution of the timer implementation in seconds */

double ptimer_resolution(void) {
  return IMPL_resolution();
}
