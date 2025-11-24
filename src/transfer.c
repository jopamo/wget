/* Per-transfer context helpers for future concurrency work.
 * src/transfer.c
 */

#include "transfer.h"

#include "wget.h"
#include "utils.h"
#include "evloop.h"

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
  ctx->state = TRANSFER_STATE_IDLE;
}

void transfer_context_prepare(struct transfer_context* ctx, const struct options* template_opts, const char* requested_uri) {
  transfer_context_init(ctx);
  transfer_context_snapshot_options(ctx, template_opts);
  transfer_context_set_requested_uri(ctx, requested_uri);
  transfer_context_bind_loop(ctx, NULL);
}

void transfer_context_free(struct transfer_context* ctx) {
  if (!ctx)
    return;

  replace_string(&ctx->requested_uri, NULL);
  replace_string(&ctx->local_file, NULL);
  ctx->progress_handle = NULL;
  ctx->scheduler = NULL;
  ctx->scheduler_internal = NULL;
  ctx->user_priority = 0;
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

void transfer_context_bind_loop(struct transfer_context* ctx, struct ev_loop* loop) {
  if (!ctx)
    return;
  if (!loop)
    loop = wget_ev_loop_get();
  ctx->loop = loop;
}

struct ev_loop* transfer_context_loop(struct transfer_context* ctx) {
  if (!ctx)
    return wget_ev_loop_get();
  if (!ctx->loop)
    ctx->loop = wget_ev_loop_get();
  return ctx->loop;
}

void transfer_context_set_state(struct transfer_context* ctx, enum transfer_state state) {
  if (!ctx)
    return;
  ctx->state = state;
}

enum transfer_state transfer_context_state(const struct transfer_context* ctx) {
  if (!ctx)
    return TRANSFER_STATE_IDLE;
  return ctx->state;
}

const char* transfer_context_state_name(enum transfer_state state) {
  switch (state) {
    case TRANSFER_STATE_IDLE:
      return "idle";
    case TRANSFER_STATE_RESOLVING:
      return "resolving";
    case TRANSFER_STATE_CONNECTING:
      return "connecting";
    case TRANSFER_STATE_TRANSFERRING:
      return "transferring";
    case TRANSFER_STATE_COMPLETED:
      return "completed";
    case TRANSFER_STATE_FAILED:
      return "failed";
    default:
      break;
  }
  return "unknown";
}
