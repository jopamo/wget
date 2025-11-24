/* CSS URL scanning is not required for sitemap tests, so provide no-op stubs. */

#include "wget.h"

#include "css-url.h"
#include "html-url.h"

void get_urls_css(struct map_context* ctx WGET_ATTR_UNUSED, int offset WGET_ATTR_UNUSED, int buf_len WGET_ATTR_UNUSED) {}

struct urlpos* get_urls_css_file(const char* file WGET_ATTR_UNUSED, const char* url WGET_ATTR_UNUSED) {
  return NULL;
}
