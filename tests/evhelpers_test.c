#include "wget.h"

#include "connect.h"
#include "evhelpers.h"
#include "evloop.h"
#include "log.h"
#include "transfer_wait.h"

#include <errno.h>
#include <ev.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char* exec_name = "evhelpers_test";
struct options opt;

static void expect(bool condition, const char* message) {
  if (!condition) {
    fprintf(stderr, "evhelpers test failed: %s\n", message);
    wget_ev_loop_deinit();
    exit(1);
  }
}

static void make_pipe(int* reader, int* writer) {
  int fds[2];
  if (pipe(fds) < 0) {
    perror("pipe");
    exit(1);
  }
  *reader = fds[0];
  *writer = fds[1];
}

static void test_wait_for_read_ready(void) {
  int reader, writer;
  make_pipe(&reader, &writer);
  write(writer, "x", 1);

  int ret = transfer_io_wait_blocking(reader, 0.1, WAIT_FOR_READ);
  expect(ret == 1, "read wait did not report readiness");

  close(reader);
  close(writer);
}

static void test_wait_timeout(void) {
  int reader, writer;
  make_pipe(&reader, &writer);

  errno = 0;
  int ret = transfer_io_wait_blocking(reader, 0.02, WAIT_FOR_READ);
  expect(ret == 0, "timeout should return 0");
  expect(errno == ETIMEDOUT, "timeout should set ETIMEDOUT");

  close(reader);
  close(writer);
}

static void test_wait_for_write_ready(void) {
  int reader, writer;
  make_pipe(&reader, &writer);

  int ret = transfer_io_wait_blocking(writer, 0.02, WAIT_FOR_WRITE);
  expect(ret == 1, "write wait should be ready");

  close(reader);
  close(writer);
}

static int timer_fired;
static ev_timer helper_timer;

static void helper_timer_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  timer_fired++;
  ev_timer_stop(EV_A_ w);
}

static void test_ev_sleep_pumps_loop(void) {
  struct ev_loop* loop = wget_ev_loop_get();
  timer_fired = 0;

  ev_timer_init(&helper_timer, helper_timer_cb, 0.01, 0);
  helper_timer.data = NULL;
  ev_timer_start(loop, &helper_timer);

  wget_ev_sleep(0.03);

  if (ev_is_active(&helper_timer))
    ev_timer_stop(loop, &helper_timer);
  expect(timer_fired == 1, "ev sleep should service timers");
}

int main(void) {
  wget_ev_loop_init();

  test_wait_for_read_ready();
  test_wait_timeout();
  test_wait_for_write_ready();
  test_ev_sleep_pumps_loop();

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
