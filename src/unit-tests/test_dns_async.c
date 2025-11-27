/*
 * Unit test for async DNS resolution.
 * src/unit-tests/test_dns_async.c
 */

#include "wget.h"
#include "dns_cares.h"
#include "evloop.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Globals required by wget_lib linkage */
struct options opt;
const char* exec_name = "unit-dns";
const char* program_name = "unit-dns";
const char* program_argstring = "unit-dns";

#ifdef HAVE_LIBCARES
#include <ares.h>
extern ares_channel ares; /* Legacy global, might be needed by host.c */
#else
void* ares;
#endif

struct test_ctx {
  int resolved_count;
  int failed_count;
  struct ev_loop* loop;
};

static void dns_cb(int status, const struct addrinfo* ai, void* arg) {
  struct test_ctx* ctx = arg;
  if (status == 0) {
    printf("Resolved successfully!\n");
    struct addrinfo* cur;
    for (cur = (struct addrinfo*)ai; cur; cur = cur->ai_next) {
      /* We could print address but just counting is enough */
    }
    ctx->resolved_count++;
  }
  else {
    printf("Resolution failed: %d\n", status);
    ctx->failed_count++;
  }
  /* Break loop to finish test */
  evloop_break(ctx->loop);
}

int main(void) {
  /* Initialize options with defaults */
  memset(&opt, 0, sizeof(opt));
  /* We might need to init opt more if dns_cares depended on it,
     but currently dns_cares only uses evloop and c-ares. */

  struct ev_loop* loop = evloop_get_default();
  struct test_ctx ctx = {0};
  ctx.loop = loop;

  if (dns_init(loop) != 0) {
    fprintf(stderr, "Failed to init dns\n");
    return 1;
  }

  /* Resolve localhost. This usually works without network. */
  printf("Starting resolution of 'localhost'...\n");
  dns_resolve_async(loop, "localhost", NULL, AF_UNSPEC, SOCK_STREAM, 0, dns_cb, &ctx);

  /* Run the loop. It should exit when dns_cb calls evloop_break */
  evloop_run(loop);

  dns_shutdown();

  if (ctx.resolved_count > 0) {
    printf("Test Passed\n");
    return 0;
  }
  else {
    printf("Test Failed\n");
    return 1;
  }
}
