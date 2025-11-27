/*
 * Event loop abstraction layer for Wget.
 * Copyright (C) 2025 Free Software Foundation, Inc.
 *
 * This file is part of GNU Wget.
 *
 * GNU Wget is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "wget.h"
#include "utils.h"
#include "evloop.h"
#include "xalloc.h"
#include <ev.h>

struct evloop_io {
  ev_io w;
  struct ev_loop* loop;
  ev_io_cb_t cb;
  void* arg;
};

struct evloop_timer {
  ev_timer w;
  struct ev_loop* loop;
  ev_timer_cb_t cb;
  void* arg;
};

/* Static Trampolines */

static void internal_io_cb(struct ev_loop* loop, ev_io* w, int revents) {
  struct evloop_io* io = (struct evloop_io*)w;
  int evloop_revents = 0;
  (void)loop;

  if (revents & EV_READ)
    evloop_revents |= EVLOOP_READ;
  if (revents & EV_WRITE)
    evloop_revents |= EVLOOP_WRITE;

  if (io->cb)
    io->cb(w->fd, evloop_revents, io->arg);
}

static void internal_timer_cb(struct ev_loop* loop, ev_timer* w, int revents) {
  struct evloop_timer* timer = (struct evloop_timer*)w;
  (void)loop;
  (void)revents;

  if (timer->cb)
    timer->cb(timer->arg);
}

static int evloop_events_to_libev(int events) {
  int libev_events = 0;
  if (events & EVLOOP_READ)
    libev_events |= EV_READ;
  if (events & EVLOOP_WRITE)
    libev_events |= EV_WRITE;
  return libev_events;
}

/* API Implementation */

struct ev_loop* evloop_get_default(void) {
  /* Use the default loop, creating it if necessary */
  return ev_default_loop(0);
}

struct evloop_io* evloop_io_start(struct ev_loop* loop, int fd, int events, ev_io_cb_t cb, void* arg) {
  struct evloop_io* io = xnew0(struct evloop_io);
  io->loop = loop;
  io->cb = cb;
  io->arg = arg;

  ev_io_init(&io->w, internal_io_cb, fd, evloop_events_to_libev(events));
  ev_io_start(loop, &io->w);

  return io;
}

void evloop_io_update(struct evloop_io* io, int events) {
  if (!io)
    return;

  ev_io_stop(io->loop, &io->w);
  ev_io_set(&io->w, io->w.fd, evloop_events_to_libev(events));
  ev_io_start(io->loop, &io->w);
}

void evloop_io_stop(struct evloop_io* io) {
  if (!io)
    return;
  ev_io_stop(io->loop, &io->w);
}

void evloop_io_free(struct evloop_io* io) {
  if (!io)
    return;
  evloop_io_stop(io);
  xfree(io);
}

struct evloop_timer* evloop_timer_start(struct ev_loop* loop, double after, double repeat, ev_timer_cb_t cb, void* arg) {
  struct evloop_timer* timer = xnew0(struct evloop_timer);
  timer->loop = loop;
  timer->cb = cb;
  timer->arg = arg;

  ev_timer_init(&timer->w, internal_timer_cb, after, repeat);
  ev_timer_start(loop, &timer->w);

  return timer;
}

void evloop_timer_reschedule(struct evloop_timer* t, double after, double repeat) {
  if (!t)
    return;

  /* libev: to change timer, use ev_timer_set + ev_timer_start, or ev_timer_again if it repeats */
  /* The safest generic way for arbitrary reschedule: */
  ev_timer_stop(t->loop, &t->w);
  ev_timer_set(&t->w, after, repeat);
  ev_timer_start(t->loop, &t->w);
}

void evloop_timer_stop(struct evloop_timer* t) {
  if (!t)
    return;
  ev_timer_stop(t->loop, &t->w);
}

void evloop_timer_free(struct evloop_timer* t) {
  if (!t)
    return;
  evloop_timer_stop(t);
  xfree(t);
}

void evloop_run(struct ev_loop* loop) {
  if (loop)
    ev_run(loop, 0);
}

void evloop_break(struct ev_loop* loop) {
  if (loop)
    ev_break(loop, EVBREAK_ALL);
}

void evloop_destroy_all(void) {
  /* No-op for now, relies on OS cleanup or specific logic if we track loops */
}