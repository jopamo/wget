/* Per-transfer context helpers for future concurrency work.
 * src/transfer.c
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

#include "transfer.h"

#include "wget.h"
#include "utils.h"

#include <string.h>

static void replace_string(char** dst, const char* src) {
  if (!dst)
    return;

  xfree(*dst);
  *dst = src ? xstrdup(src) : NULL;
}

void transfer_context_init(struct transfer_context* ctx) {
  if (!ctx)
    return;

  memset(ctx, 0, sizeof(*ctx));
}

void transfer_context_prepare(struct transfer_context* ctx, const struct options* template_opts, const char* requested_uri) {
  transfer_context_init(ctx);
  transfer_context_snapshot_options(ctx, template_opts);
  transfer_context_set_requested_uri(ctx, requested_uri);
}

void transfer_context_free(struct transfer_context* ctx) {
  if (!ctx)
    return;

  replace_string(&ctx->requested_uri, NULL);
  replace_string(&ctx->local_file, NULL);
  ctx->progress_handle = NULL;
}

void transfer_context_snapshot_options(struct transfer_context* ctx, const struct options* template_opts) {
  if (!ctx || !template_opts)
    return;

  ctx->options = *template_opts;
  ctx->has_options = true;
}

void transfer_context_set_requested_uri(struct transfer_context* ctx, const char* uri) {
  if (!ctx)
    return;
  replace_string(&ctx->requested_uri, uri);
}

void transfer_context_set_local_file(struct transfer_context* ctx, const char* path) {
  if (!ctx)
    return;
  replace_string(&ctx->local_file, path);
}

void transfer_context_set_progress_handle(struct transfer_context* ctx, void* progress) {
  if (!ctx)
    return;

  ctx->progress_handle = progress;
}

void transfer_context_record_stats(struct transfer_context* ctx, wgint bytes, double seconds) {
  if (!ctx)
    return;

  ctx->stats.bytes_downloaded += bytes;
  ctx->stats.seconds_spent += seconds;
}
