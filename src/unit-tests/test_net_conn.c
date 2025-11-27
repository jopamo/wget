/*
 * Unit test for net_conn (Phase 3).
 * src/unit-tests/test_net_conn.c
 */

#include "wget.h"
#include "net_conn.h"
#include "evloop.h"
#include "dns_cares.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#define LOG(fmt, ...)                                            \
  do {                                                           \
    fprintf(stdout, "[test_net_conn] " fmt "\n", ##__VA_ARGS__); \
    fflush(stdout);                                              \
  } while (0)

/* Globals required by wget_lib linkage */
struct options opt;
const char* exec_name = "unit-net-conn";
const char* program_name = "unit-net-conn";
const char* program_argstring = "unit-net-conn";

#ifdef HAVE_LIBCARES
#include <ares.h>
ares_channel ares;
#else
void* ares;
#endif

struct test_ctx {
  struct ev_loop* loop;
  struct net_conn* conn;
  int listen_fd;
  int accepted_fd;
  struct evloop_io* listen_io;
  struct evloop_io* accepted_io;
  int stage;
  int fail;
};

static void listen_cb(int fd, int revents, void* arg);
static void conn_ready(struct net_conn* c, void* arg);
static void conn_error(struct net_conn* c, void* arg);
static void conn_readable(struct net_conn* c, void* arg);

/* Accepted socket read callback */
static void accepted_read_cb(int fd, int revents, void* arg) {
  LOG("accepted_read_cb: fd=%d, revents=%d", fd, revents);
  struct test_ctx* ctx = arg;
  char buf[128];
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n > 0) {
    buf[n] = 0;
    LOG("accepted_read_cb: received %s", buf);
    if (strcmp(buf, "PING") == 0) {
      /* Send Pong */
      ssize_t written = write(fd, "PONG", 4);
      if (written != 4) {
        LOG("accepted_read_cb: failed to write PONG, written=%zd", written);
      }
      else {
        LOG("accepted_read_cb: sent PONG");
      }
      ctx->stage = 2;
    }
  }
}

static void listen_cb(int fd, int revents, void* arg) {
  LOG("listen_cb: fd=%d, revents=%d", fd, revents);
  struct test_ctx* ctx = arg;
  struct sockaddr_in cli_addr;
  socklen_t len = sizeof(cli_addr);
  int client = accept(fd, (struct sockaddr*)&cli_addr, &len);

  if (client >= 0) {
    LOG("Server accepted connection");
    fcntl(client, F_SETFL, O_NONBLOCK);
    ctx->accepted_fd = client;
    ctx->accepted_io = evloop_io_start(ctx->loop, client, EVLOOP_READ, accepted_read_cb, ctx);

    /* Stop listening to prevent noise if multiple attempts? */
    /* We keep it open but maybe stop watcher if we only want one. */
  }
}

static void conn_ready(struct net_conn* c, void* arg) {
  struct test_ctx* ctx = arg;
  LOG("Client Connected!");

  /* Send PING */
  ssize_t n = conn_try_write(c, "PING", 4);
  if (n != 4) {
    LOG("Client failed to write PING, written=%zd, errno=%d", n, errno);
    ctx->fail = 1;
    evloop_break(ctx->loop);
    return;
  }
  LOG("Client sent PING");

  /* Wait for PONG */
  LOG("Client attempting to set readable callback");
  conn_set_readable_callback(c, conn_readable, ctx);
  LOG("Client set readable callback");
  ctx->stage = 1;
}

static void conn_error(struct net_conn* c, void* arg) {
  struct test_ctx* ctx = arg;
  LOG("Client Error: %s", conn_get_error_msg(c));
  ctx->fail = 1;
  evloop_break(ctx->loop);
}

static void conn_readable(struct net_conn* c, void* arg) {
  struct test_ctx* ctx = arg;
  char buf[128];
  ssize_t n = conn_try_read(c, buf, sizeof(buf) - 1);

  if (n > 0) {
    buf[n] = 0;
    LOG("Client received: %s", buf);
    if (strcmp(buf, "PONG") == 0) {
      LOG("Test Passed!");
      ctx->fail = 0;
      evloop_break(ctx->loop);
    }
  }
  else if (n == 0) {
    LOG("Client received EOF");
    ctx->fail = 1; /* Unexpected EOF before PONG */
    evloop_break(ctx->loop);
  }
  else {
    LOG("Client read error: %s", strerror(errno));
    ctx->fail = 1;
    evloop_break(ctx->loop);
  }
}

int main(void) {
  memset(&opt, 0, sizeof(opt));

  struct ev_loop* loop = evloop_get_default();
  struct test_ctx ctx = {0};
  ctx.loop = loop;

  /* Initialize DNS */
  if (dns_init(loop) != 0) {
    fprintf(stderr, "DNS init failed\n");
    return 1;
  }

  /* Setup Listener */
  int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0; /* Let OS pick port */

  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind");
    return 1;
  }
  listen(s, 1);

  socklen_t len = sizeof(addr);
  getsockname(s, (struct sockaddr*)&addr, &len);
  int port = ntohs(addr.sin_port);
  char port_str[16];
  snprintf(port_str, sizeof(port_str), "%d", port);

  LOG("Listening on port %d", port);
  ctx.listen_fd = s;
  ctx.listen_io = evloop_io_start(loop, s, EVLOOP_READ, listen_cb, &ctx);

  /* Start Client Connection */
  /* Use 127.0.0.1 to ensure IPv4 matching the listener */
  LOG("Connecting to 127.0.0.1:%s...", port_str);
  ctx.conn = conn_new(loop, "127.0.0.1", port_str, false, conn_ready, conn_error, &ctx);

  /* Run */
  evloop_run(loop);

  /* Cleanup */
  conn_close(ctx.conn);
  dns_shutdown();
  if (ctx.accepted_io)
    evloop_io_free(ctx.accepted_io);
  if (ctx.listen_io)
    evloop_io_free(ctx.listen_io);
  if (ctx.accepted_fd >= 0)
    close(ctx.accepted_fd);
  close(ctx.listen_fd);

  return ctx.fail;
}
