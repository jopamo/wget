/*
 * Asynchronous DNS resolution using c-ares and libev.
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

#ifndef WGET_DNS_CARES_H
#define WGET_DNS_CARES_H

#include <ares.h>
#include <netdb.h>

/* Forward declaration */
struct ev_loop;

/* Callback type for async resolution */
typedef void (*dns_result_cb)(int status, const struct addrinfo* ai, void* arg);

/* Initialization and Cleanup */
int dns_init(struct ev_loop* loop);
void dns_shutdown(void);

/* Public Async API */
void dns_resolve_async(struct ev_loop* loop, const char* hostname, const char* service, int family, int socktype, int protocol, dns_result_cb cb, void* arg);

#endif /* WGET_DNS_CARES_H */
