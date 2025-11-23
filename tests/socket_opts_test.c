#include "config.h"

#include "wget.h"

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "socket_opts.h"

static void reset_opts(struct options* opt) {
  memset(opt, 0, sizeof(*opt));
}

int main(void) {
  struct options opt;
  reset_opts(&opt);

  assert(wget_socket_rcvbuf_value(&opt) == 0);
  assert(wget_socket_sndbuf_value(&opt) == 0);
  assert(!wget_socket_use_nodelay(&opt));

  opt.tcp_rcvbuf = 16384;
  assert(wget_socket_rcvbuf_value(&opt) == 16384);

  opt.tcp_rcvbuf = (wgint)INT_MAX + 1024;
  assert(wget_socket_rcvbuf_value(&opt) == INT_MAX);

  opt.tcp_rcvbuf = -1;
  assert(wget_socket_rcvbuf_value(&opt) == 0);

  opt.tcp_rcvbuf = 0;
  opt.limit_rate = 4096;
  assert(wget_socket_rcvbuf_value(&opt) == 4096);

  opt.limit_rate = 100;
  assert(wget_socket_rcvbuf_value(&opt) == 512);

  opt.limit_rate = 9000;
  assert(wget_socket_rcvbuf_value(&opt) == 0);

  opt.limit_rate = 0;
  opt.tcp_sndbuf = 2048;
  assert(wget_socket_sndbuf_value(&opt) == 2048);

  opt.tcp_sndbuf = (wgint)INT_MAX + 2048;
  assert(wget_socket_sndbuf_value(&opt) == INT_MAX);

  opt.tcp_sndbuf = 0;
  opt.tcp_nodelay = true;
  assert(wget_socket_use_nodelay(&opt));

  return 0;
}
