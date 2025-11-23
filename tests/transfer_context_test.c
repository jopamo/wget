/* Tests for transfer_context helpers.
 * tests/transfer_context_test.c
 */

#include "transfer.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "evloop.h"
static void validate_state_names(void) {
  assert(strcmp(transfer_context_state_name(TRANSFER_STATE_IDLE), "idle") == 0);
  assert(strcmp(transfer_context_state_name(TRANSFER_STATE_CONNECTING), "connecting") == 0);
  assert(strcmp(transfer_context_state_name(TRANSFER_STATE_COMPLETED), "completed") == 0);
  assert(strcmp(transfer_context_state_name(TRANSFER_STATE_FAILED), "failed") == 0);
}

static void test_basic_lifecycle(void) {
  struct transfer_context ctx;
  struct options template_opts;

  memset(&ctx, 0, sizeof(ctx));
  memset(&template_opts, 0, sizeof(template_opts));

  template_opts.limit_rate = 2048;
  template_opts.recursive = true;

  transfer_context_prepare(&ctx, &template_opts, "http://example.test/");
  assert(ctx.has_options);
  assert(ctx.options.limit_rate == template_opts.limit_rate);
  assert(ctx.options.recursive == template_opts.recursive);
  assert(strcmp(ctx.requested_uri, "http://example.test/") == 0);

  transfer_context_set_state(&ctx, TRANSFER_STATE_CONNECTING);
  assert(transfer_context_state(&ctx) == TRANSFER_STATE_CONNECTING);

  transfer_context_set_local_file(&ctx, "/tmp/out");
  assert(strcmp(ctx.local_file, "/tmp/out") == 0);

  transfer_context_set_progress_handle(&ctx, (void*)0x1);
  assert(ctx.progress_handle == (void*)0x1);

  transfer_context_record_stats(&ctx, 512, 1.5);
  transfer_context_record_stats(&ctx, 1024, 0.5);
  assert(ctx.stats.bytes_downloaded == 1536);
  assert(ctx.stats.seconds_spent > 1.9 && ctx.stats.seconds_spent < 2.1);

  struct ev_loop* bound_loop = transfer_context_loop(&ctx);
  assert(bound_loop == wget_ev_loop_get());

  transfer_context_bind_loop(&ctx, bound_loop);
  assert(transfer_context_loop(&ctx) == bound_loop);

  transfer_context_free(&ctx);
  assert(ctx.requested_uri == NULL);
  assert(ctx.local_file == NULL);
  assert(ctx.progress_handle == NULL);
}

int main(void) {
  validate_state_names();
  test_basic_lifecycle();
  return 0;
}
