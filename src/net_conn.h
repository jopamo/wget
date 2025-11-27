/*
 * Non-blocking connection object for Wget.
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

#ifndef WGET_NET_CONN_H
#define WGET_NET_CONN_H

#include <stdbool.h>
#include <sys/types.h>

/* Forward declarations */
struct ev_loop;
struct net_conn;

/* Connection States */
enum conn_state { CONN_INIT, CONN_RESOLVING, CONN_CONNECTING, CONN_TLS_HANDSHAKE, CONN_READY, CONN_CLOSED, CONN_ERROR };

/* Callback type for connection events */
typedef void (*conn_event_cb)(struct net_conn* c, void* arg);

/* Constructor */
struct net_conn* conn_new(struct ev_loop* loop, const char* host, const char* port, bool use_tls, conn_event_cb on_ready, conn_event_cb on_error, void* arg);

/* Cleanup */
void conn_close(struct net_conn* c);

/* IO Operations (Non-blocking) */
ssize_t conn_try_read(struct net_conn* c, void* buf, size_t len);
ssize_t conn_try_write(struct net_conn* c, const void* buf, size_t len);

/* Event Registration */
void conn_set_readable_callback(struct net_conn* c, conn_event_cb cb, void* arg);
void conn_set_writable_callback(struct net_conn* c, conn_event_cb cb, void* arg);

/* Accessors */
enum conn_state conn_get_state(struct net_conn* c);
const char* conn_get_error_msg(struct net_conn* c);

#endif /* WGET_NET_CONN_H */
