/* Central libev event loop driver and orchestration
 * src/evloop.c
 */

#include "wget.h"

#include <ev.h>
#include <stdlib.h>

#include "evloop.h"
#include "exits.h"
#include "log.h"
#include "threading.h"

static struct ev_loop* main_loop;
static ev_async wake_async;
static atomic_bool wake_started;
static unsigned int active_transfer_machines;
static wget_async_mailbox_t ev_async_mailbox;

static void evloop_run_mailbox(void) {
  wget_async_task_t* list = wget_async_mailbox_acquire_all(&ev_async_mailbox);
  if (!list)
    return;

  list = wget_async_mailbox_reverse(list);
  while (list) {
    wget_async_task_t* current = list;
    list = list->next;
    if (current->fn)
      current->fn(current->arg);
    free(current);
  }
}

static void evloop_wake_cb(EV_P_ ev_async* w WGET_ATTR_UNUSED, int revents WGET_ATTR_UNUSED) {
  evloop_run_mailbox();
}

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
  wget_async_mailbox_init(&ev_async_mailbox);
  atomic_store_explicit(&wake_started, true, memory_order_release);
}

void wget_ev_loop_deinit(void) {
  if (!main_loop)
    return;

  if (atomic_load_explicit(&wake_started, memory_order_acquire)) {
    ev_async_stop(main_loop, &wake_async);
    atomic_store_explicit(&wake_started, false, memory_order_release);
  }

  ev_loop_destroy(main_loop);
  main_loop = NULL;

  /* Ensure we do not leak deferred tasks if we're shutting down. */
  evloop_run_mailbox();
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
  if (main_loop && atomic_load_explicit(&wake_started, memory_order_acquire))
    ev_async_send(main_loop, &wake_async);
}

void wget_ev_loop_transfer_ref(void) {
  ++active_transfer_machines;
}

void wget_ev_loop_transfer_unref(void) {
  if (active_transfer_machines == 0)
    return;
  --active_transfer_machines;
}

bool wget_ev_loop_has_active_transfers(void) {
  return active_transfer_machines > 0;
}

/* LEGACY_BLOCKING: spins the main loop until all transfers complete. */
void wget_ev_loop_run_transfers(void) {
  struct ev_loop* loop = wget_ev_loop_get();
  while (wget_ev_loop_has_active_transfers())
    ev_run(loop, EVRUN_ONCE);
  evloop_run_mailbox();
}

bool wget_ev_loop_post_async(wget_ev_loop_async_cb cb, void* arg) {
  if (!cb)
    return false;

  wget_ev_loop_get();

  wget_async_task_t* task = xmalloc(sizeof(*task));
  task->fn = cb;
  task->arg = arg;
  task->next = NULL;

  wget_async_mailbox_push(&ev_async_mailbox, task);
  wget_ev_loop_wakeup();
  return true;
}
