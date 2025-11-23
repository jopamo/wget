/* Per-transfer context helpers for future concurrency work.
 * src/transfer.h
 *
 * Copyright (C) 2024 Free Software Foundation,
 * Inc.
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
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TRANSFER_H
#define TRANSFER_H

#include "wget.h"
#include "evloop.h"

struct ev_loop;

enum transfer_state {
  TRANSFER_STATE_IDLE = 0,
  TRANSFER_STATE_RESOLVING,
  TRANSFER_STATE_CONNECTING,
  TRANSFER_STATE_TRANSFERRING,
  TRANSFER_STATE_COMPLETED,
  TRANSFER_STATE_FAILED
};

struct transfer_stats {
  wgint bytes_downloaded;
  double seconds_spent;
};

struct transfer_context {
  struct options options; /* Snapshot of the global options. */
  bool has_options;
  char* requested_uri;
  char* local_file;
  void* progress_handle;
  struct transfer_stats stats;
  struct ev_loop* loop;
  enum transfer_state state;
};

void transfer_context_init(struct transfer_context* ctx);
void transfer_context_prepare(struct transfer_context* ctx, const struct options* template_opts, const char* requested_uri);
void transfer_context_free(struct transfer_context* ctx);
void transfer_context_snapshot_options(struct transfer_context* ctx, const struct options* template_opts);
void transfer_context_set_requested_uri(struct transfer_context* ctx, const char* uri);
void transfer_context_set_local_file(struct transfer_context* ctx, const char* path);
void transfer_context_set_progress_handle(struct transfer_context* ctx, void* progress);
void transfer_context_record_stats(struct transfer_context* ctx, wgint bytes, double seconds);
void transfer_context_bind_loop(struct transfer_context* ctx, struct ev_loop* loop);
struct ev_loop* transfer_context_loop(struct transfer_context* ctx);
void transfer_context_set_state(struct transfer_context* ctx, enum transfer_state state);
enum transfer_state transfer_context_state(const struct transfer_context* ctx);
const char* transfer_context_state_name(enum transfer_state state);

#endif /* TRANSFER_H */
