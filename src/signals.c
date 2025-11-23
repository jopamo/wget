/* Signal subscription and dispatch helpers built on libev
 * src/signals.c
 */

#include "wget.h"

#include <ev.h>

#include "evloop.h"
#include "utils.h"
#include "signals.h"
#include "xalloc.h"

struct signal_subscription {
  ev_signal watcher;
  wget_signal_handler handler;
  int signum;
  struct signal_subscription* next;
  bool started;
};

static struct signal_subscription* signal_subscriptions;
static struct ev_loop* signals_loop;

static void dispatch_signal(EV_P_ ev_signal* w, int revents WGET_ATTR_UNUSED) {
  struct signal_subscription* subscription = w->data;
  if (subscription && subscription->handler)
    subscription->handler(subscription->signum);
}

static struct signal_subscription* find_subscription(int signum) {
  for (struct signal_subscription* sub = signal_subscriptions; sub; sub = sub->next)
    if (sub->signum == signum)
      return sub;
  return NULL;
}

void wget_signals_watch(int signum, wget_signal_handler handler) {
  struct signal_subscription* subscription = find_subscription(signum);

  if (subscription) {
    subscription->handler = handler;
    return;
  }

  subscription = xcalloc(1, sizeof(*subscription));
  subscription->signum = signum;
  subscription->handler = handler;

  if (!signals_loop)
    signals_loop = wget_ev_loop_get();

  ev_signal_init(&subscription->watcher, dispatch_signal, signum);
  subscription->watcher.data = subscription;
  ev_signal_start(signals_loop, &subscription->watcher);
  subscription->started = true;

  subscription->next = signal_subscriptions;
  signal_subscriptions = subscription;
}

void wget_signals_unwatch(int signum) {
  struct signal_subscription *prev = NULL, *sub = signal_subscriptions;
  while (sub) {
    if (sub->signum == signum) {
      if (signals_loop && sub->started)
        ev_signal_stop(signals_loop, &sub->watcher);
      if (prev)
        prev->next = sub->next;
      else
        signal_subscriptions = sub->next;
      xfree(sub);
      break;
    }
    prev = sub;
    sub = sub->next;
  }
}

void wget_signals_shutdown(void) {
  struct signal_subscription* sub = signal_subscriptions;

  if (!signals_loop && wget_ev_loop_is_initialized())
    signals_loop = wget_ev_loop_get();

  while (sub) {
    struct signal_subscription* next = sub->next;
    if (signals_loop && sub->started)
      ev_signal_stop(signals_loop, &sub->watcher);
    xfree(sub);
    sub = next;
  }

  signal_subscriptions = NULL;
  signals_loop = NULL;
}
