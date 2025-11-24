#include "wget.h"

#include "evloop.h"
#include "signals.h"
#include "log.h"

#include <ev.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Provide minimal globals the production objects expect. */
const char* exec_name = "signal_helpers_test";
struct options opt;

static volatile sig_atomic_t handler_a_hits;
static volatile sig_atomic_t handler_b_hits;
static volatile sig_atomic_t observed_signum;

#if defined(SIGUSR1)
#define TEST_SIGNAL SIGUSR1
#elif defined(SIGWINCH)
#define TEST_SIGNAL SIGWINCH
#else
#define TEST_SIGNAL SIGINT
#endif

static void handler_a(int signum) {
  handler_a_hits++;
  observed_signum = signum;
  wget_ev_loop_break();
}

static void handler_b(int signum) {
  handler_b_hits++;
  observed_signum = signum;
  wget_ev_loop_break();
}

static bool exercise_signal_once(void) {
  sig_atomic_t before = handler_a_hits + handler_b_hits;
  ev_feed_signal_event(wget_ev_loop_get(), TEST_SIGNAL);
  wget_ev_loop_wakeup();

  struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000};
  for (int i = 0; i < 1000; ++i) {
    if (handler_a_hits + handler_b_hits > before)
      return true;
    nanosleep(&ts, NULL);
  }
  return handler_a_hits + handler_b_hits > before;
}

static void expect(bool condition, const char* message) {
  if (!condition) {
    fprintf(stderr, "signal helpers test failed: %s\n", message);
    wget_signals_shutdown();
    wget_ev_loop_deinit();
    exit(1);
  }
}

int main(void) {
  /* Ensures we have a loop ready before registering watchers. */
  wget_ev_loop_init();

  handler_a_hits = 0;
  handler_b_hits = 0;
  observed_signum = 0;

  wget_signals_watch(TEST_SIGNAL, handler_a);
  expect(exercise_signal_once(), "handler A did not trigger");
  expect(handler_a_hits == 1, "handler A not triggered");
  expect(observed_signum == TEST_SIGNAL, "handler A saw wrong signum");

  wget_signals_watch(TEST_SIGNAL, handler_b);
  expect(exercise_signal_once(), "handler B did not trigger");
  expect(handler_a_hits == 1, "handler A should not fire twice");
  expect(handler_b_hits == 1, "handler B should fire once");
  expect(observed_signum == TEST_SIGNAL, "handler B saw wrong signum");

  wget_signals_unwatch(TEST_SIGNAL);
  expect(!exercise_signal_once(), "handler invoked after unwatch");
  expect(handler_a_hits == 1 && handler_b_hits == 1, "handler invoked after unwatch");

  wget_signals_shutdown();
  wget_ev_loop_deinit();
  return 0;
}

/* ---- Logging stubs ---- */
void logprintf(enum log_options opt WGET_ATTR_UNUSED, const char* fmt WGET_ATTR_UNUSED, ...) {
  va_list args;
  va_start(args, fmt);
  va_end(args);
}

void debug_logprintf(const char* fmt WGET_ATTR_UNUSED, ...) {
  va_list args;
  va_start(args, fmt);
  va_end(args);
}

void logputs(enum log_options opt WGET_ATTR_UNUSED, const char* msg WGET_ATTR_UNUSED) {}

void logflush(void) {}

void log_set_flush(bool flush WGET_ATTR_UNUSED) {}

bool log_set_save_context(bool save WGET_ATTR_UNUSED) {
  return false;
}
