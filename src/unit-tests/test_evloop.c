/*
 * Unit test for event loop wrapper (evloop).
 * src/unit-tests/test_evloop.c
 */

#include "wget.h"
#include "evloop.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

/* Globals required by wget_lib linkage */
struct options opt;
const char* exec_name = "unit-evloop";
const char* program_name = "unit-evloop";
const char* program_argstring = "unit-evloop";

#ifdef HAVE_LIBCARES
#include <ares.h>
ares_channel ares;
#else
void* ares;
#endif

static struct ev_loop* loop;
static int timer_count = 0;
static int io_count = 0;

/* Callback that increments counter and stops loop */
static void stop_timer_cb(void* arg) {
  (void)arg;
  timer_count++;
  evloop_break(loop);
}

/* Callback for IO read */
static void read_cb(int fd, int revents, void* arg) {
  (void)arg;
  (void)revents;
  io_count++;
  char buf[16];
  ssize_t r = read(fd, buf, sizeof(buf));
  (void)r;
  evloop_break(loop);
}

int main(void) {
  /* Initialize global options */
  memset(&opt, 0, sizeof(opt));

  loop = evloop_get_default();
  if (!loop) {
    fprintf(stderr, "Failed to get default loop\n");
    return 1;
  }

  /* --- Test 1: One-shot Timer --- */
  printf("Test 1: One-shot Timer... ");
  timer_count = 0;
  struct evloop_timer* t1 = evloop_timer_start(loop, 0.01, 0.0, stop_timer_cb, NULL);

  evloop_run(loop);

  if (timer_count == 1) {
    printf("OK\n");
  }
  else {
    printf("FAILED (count=%d)\n", timer_count);
    return 1;
  }
  evloop_timer_free(t1);

  /* --- Test 2: IO Watcher (Pipe) --- */
  printf("Test 2: IO Watcher (Pipe)... ");
  int pfd[2];
  if (pipe(pfd) != 0) {
    perror("pipe");
    return 1;
  }

  /* Set non-blocking */
  fcntl(pfd[0], F_SETFL, O_NONBLOCK);
  fcntl(pfd[1], F_SETFL, O_NONBLOCK);

  io_count = 0;
  struct evloop_io* io = evloop_io_start(loop, pfd[0], EVLOOP_READ, read_cb, NULL);

  /* Write to pipe to trigger read event */
  if (write(pfd[1], "A", 1) != 1) {
    perror("write");
    return 1;
  }

  evloop_run(loop);

  if (io_count == 1) {
    printf("OK\n");
  }
  else {
    printf("FAILED (count=%d)\n", io_count);
    return 1;
  }

  evloop_io_free(io);
  close(pfd[0]);
  close(pfd[1]);

  /* Cleanup */
  // evloop_destroy_all(); /* Not strictly needed but good practice if implemented */

  return 0;
}
