/* Common stubs shared by the lightweight libev tests.
 * tests/test_stubs.c
 */

#include "wget.h"

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

struct options opt;
const char* exec_name = "tests";

void log_set_warc_log_fp(FILE* fp WGET_ATTR_UNUSED) {}

void logprintf(enum log_options mode WGET_ATTR_UNUSED, const char* fmt WGET_ATTR_UNUSED, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_end(ap);
}

void debug_logprintf(const char* fmt WGET_ATTR_UNUSED, ...) {
  va_list ap;
  va_start(ap, fmt);
  va_end(ap);
}

void logputs(enum log_options mode WGET_ATTR_UNUSED, const char* s WGET_ATTR_UNUSED) {}
void logflush(void) {}
void log_set_flush(bool enabled WGET_ATTR_UNUSED) {}
bool log_set_save_context(bool enabled WGET_ATTR_UNUSED) {
  return false;
}

void log_init(const char* file WGET_ATTR_UNUSED, bool append WGET_ATTR_UNUSED) {}
void log_close(void) {}
void log_cleanup(void) {}
void log_request_redirect_output(const char* path WGET_ATTR_UNUSED) {}
void redirect_output(bool state WGET_ATTR_UNUSED, const char* file WGET_ATTR_UNUSED) {}

const char* escnonprint(const char* input) {
  return input;
}

const char* escnonprint_uri(const char* input) {
  return input;
}
