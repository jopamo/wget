/* http_response/http_stat helper tests.
 * tests/http_response_test.c
 */

#include "config.h"

#include "wget.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "http_response.h"
#include "http_internal.h"
#include "url.h"

static struct http_response* parse_response(const char* text) {
  return http_response_parse(xstrdup(text));
}

static void test_http_stat_reset(void) {
  struct http_stat hs;
  memset(&hs, 0, sizeof(hs));
  hs.len = 42;
  hs.contlen = 100;
  hs.res = 1;
  hs.rderrmsg = xstrdup("io");
  hs.newloc = xstrdup("https://example.com/old");
  hs.remote_time = xstrdup("Thu, 01 Jan 1970 00:00:00 GMT");
  hs.error = xstrdup("old");
  hs.message = xstrdup("msg");
  hs.local_encoding = ENC_GZIP;
  hs.remote_encoding = ENC_DEFLATE;

  http_stat_reset(&hs);

  assert(hs.len == 0);
  assert(hs.contlen == -1);
  assert(hs.res == -1);
  assert(hs.rderrmsg == NULL);
  assert(hs.newloc == NULL);
  assert(hs.remote_time == NULL);
  assert(hs.error == NULL);
  assert(hs.message == NULL);
  assert(hs.local_encoding == ENC_NONE);
  assert(hs.remote_encoding == ENC_NONE);
}

static void test_http_stat_message_helpers(void) {
  struct http_stat hs;
  memset(&hs, 0, sizeof(hs));

  http_stat_set_message(&hs, "alpha");
  assert(hs.message && strcmp(hs.message, "alpha") == 0);
  http_stat_set_message(&hs, NULL);
  assert(hs.message == NULL);

  http_stat_record_status(&hs, 200, "OK");
  assert(hs.statcode == 200);
  assert(hs.error && strcmp(hs.error, "OK") == 0);
  assert(hs.message && strcmp(hs.message, "OK") == 0);

  http_stat_record_status(&hs, -1, NULL);
  assert(hs.statcode == -1);
  assert(hs.error && strcmp(hs.error, _("Malformed status line")) == 0);

  http_stat_reset(&hs);
}

static void test_http_stat_capture_headers(void) {
  static const char* raw =
    "HTTP/1.1 302 Found\r\n"
    "Location: https://example.com/new\r\n"
    "X-Archive-Orig-last-modified: Tue, 15 Nov 1994 08:12:31 GMT\r\n"
    "Content-Encoding: gzip\r\n"
    "\r\n";

  struct http_response* resp = parse_response(raw);
  struct http_stat hs;
  struct url u;
  char scratch[64];

  memset(&hs, 0, sizeof(hs));
  memset(&u, 0, sizeof(u));
  u.file = xstrdup("archive.tgz");

  opt.compression = compression_gzip;
  http_stat_capture_headers(&hs, resp, &u, "text/plain", scratch, sizeof(scratch));

  assert(hs.newloc && strcmp(hs.newloc, "https://example.com/new") == 0);
  assert(hs.remote_time && strcmp(hs.remote_time, "Tue, 15 Nov 1994 08:12:31 GMT") == 0);
  assert(hs.local_encoding == ENC_NONE);
  assert(hs.remote_encoding == ENC_NONE);

  free(u.file);
  http_response_free(&resp);
  http_stat_release(&hs);
}

static void test_http_stat_release(void) {
  struct http_stat hs;
  memset(&hs, 0, sizeof(hs));
  hs.newloc = xstrdup("https://example.test");
  hs.remote_time = xstrdup("Fri, 02 Jun 2023 10:00:00 GMT");
  hs.local_file = xstrdup("file");
  hs.orig_file_name = xstrdup("file.orig");
  hs.rderrmsg = xstrdup("err");
  hs.error = xstrdup("fail");
  hs.message = xstrdup("msg");

  http_stat_release(&hs);

  assert(hs.newloc == NULL);
  assert(hs.remote_time == NULL);
  assert(hs.local_file == NULL);
  assert(hs.orig_file_name == NULL);
  assert(hs.rderrmsg == NULL);
  assert(hs.error == NULL);
  assert(hs.message == NULL);
}

int main(void) {
  test_http_stat_reset();
  test_http_stat_message_helpers();
  test_http_stat_capture_headers();
  test_http_stat_release();
  return 0;
}
