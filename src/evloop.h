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

#ifndef WGET_EVLOOP_H
#define WGET_EVLOOP_H

#include <stdbool.h>

/* Forward declaration of libev loop struct */
struct ev_loop;

/* Opaque wrapper types */
struct evloop_io;
struct evloop_timer;

/* Callback types */
typedef void (*ev_io_cb_t)(int fd, int revents, void* arg);
typedef void (*ev_timer_cb_t)(void* arg);

/* Event constants (matching libev/poll) */
#define EVLOOP_READ 0x01  /* EV_READ */
#define EVLOOP_WRITE 0x02 /* EV_WRITE */

/* API */

/* Get the default event loop (singleton) */
struct ev_loop* evloop_get_default(void);

/* I/O Watchers */
struct evloop_io* evloop_io_start(struct ev_loop* loop, int fd, int events, ev_io_cb_t cb, void* arg);
void evloop_io_update(struct evloop_io* io, int events);
void evloop_io_stop(struct evloop_io* io);
void evloop_io_free(struct evloop_io* io);

/* Timer Watchers */
struct evloop_timer* evloop_timer_start(struct ev_loop* loop, double after, double repeat, ev_timer_cb_t cb, void* arg);
void evloop_timer_reschedule(struct evloop_timer* t, double after, double repeat);
void evloop_timer_stop(struct evloop_timer* t);
void evloop_timer_free(struct evloop_timer* t);

/* Loop Control */
void evloop_run(struct ev_loop* loop);
void evloop_break(struct ev_loop* loop);

/* Cleanup (optional, mostly for clean shutdown in tests/valgrind) */
void evloop_destroy_all(void);

#endif /* WGET_EVLOOP_H */
