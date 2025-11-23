/* Central libev event loop driver and orchestration
 * src/evloop.c
 */

#include "wget.h"

#include <ev.h>
#include <stdlib.h>

#include "evloop.h"
#include "exits.h"
#include "log.h"

static struct ev_loop* main_loop;
static ev_async wake_async;
static bool wake_started;

static void evloop_wake_cb(EV_P_ ev_async* w WGET_ATTR_UNUSED, int revents WGET_ATTR_UNUSED) {}

void wget_ev_loop_init(void) {
  if (main_loop)
    return;

  main_loop = ev_loop_new(EVFLAG_AUTO);
  if (!main_loop) {
    /* Should never happen, but abort early so callers don't dereference NULL. */
    logprintf(LOG_NOTQUIET, _("Failed to initialize libev event loop.\n"));
    exit(WGET_EXIT_GENERIC_ERROR);
  }

  ev_async_init(&wake_async, evloop_wake_cb);
  ev_async_start(main_loop, &wake_async);
  wake_started = true;
}

void wget_ev_loop_deinit(void) {
  if (!main_loop)
    return;

  if (wake_started) {
    ev_async_stop(main_loop, &wake_async);
    wake_started = false;
  }

  ev_loop_destroy(main_loop);
  main_loop = NULL;
}

struct ev_loop* wget_ev_loop_get(void) {
  if (!main_loop)
    wget_ev_loop_init();
  return main_loop;
}

bool wget_ev_loop_is_initialized(void) {
  return main_loop != NULL;
}

void wget_ev_loop_run(void) {
  ev_run(wget_ev_loop_get(), 0);
}

void wget_ev_loop_run_once(void) {
  ev_run(wget_ev_loop_get(), EVRUN_ONCE);
}

void wget_ev_loop_break(void) {
  if (main_loop)
    ev_break(main_loop, EVBREAK_ALL);
}

void wget_ev_loop_wakeup(void) {
  if (main_loop && wake_started)
    ev_async_send(main_loop, &wake_async);
}
