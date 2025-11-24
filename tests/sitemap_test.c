/* Unit tests for sitemap parsing helpers. */

#include "wget.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "html-url.h"
#include "recur.h"
#include "threading.h"
#include "evloop.h"

static char* write_temp_file(const char* contents) {
  char template[] = "/tmp/wget_sitemap_XXXXXX";
  int fd = mkstemp(template);
  if (fd < 0)
    return NULL;
  size_t len = strlen(contents);
  if (write(fd, contents, len) != (ssize_t)len) {
    close(fd);
    unlink(template);
    return NULL;
  }
  close(fd);
  return xstrdup(template);
}

static void expect_urls(struct urlpos* urls, const char** expected, size_t expected_count) {
  size_t seen = 0;
  for (struct urlpos* current = urls; current; current = current->next) {
    assert(seen < expected_count);
    assert(current->url);
    assert(current->url->url);
    assert(!strcmp(current->url->url, expected[seen]));
    assert(current->link_expect_html);
    ++seen;
  }
  assert(seen == expected_count);
}

int main(void) {
  opt.locale = "C";
  opt.enable_iri = false;

  const char* sitemap_xml =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
      "<url><loc>https://example.com/static/page.html</loc></url>"
      "<url><loc>/relative/docs/page-two.html</loc></url>"
      "</urlset>";

  char* sitemap_path = write_temp_file(sitemap_xml);
  assert(sitemap_path != NULL);

  const char* expected_urls[] = {
      "https://example.com/static/page.html",
      "https://example.com/base/relative/docs/page-two.html",
  };

  const char* base_url = "https://example.com/base/index.html";
  assert(wget_recur_file_looks_like_sitemap(sitemap_path));

  struct urlpos* urls = get_urls_sitemap(sitemap_path, base_url, NULL);
  assert(urls != NULL);
  expect_urls(urls, expected_urls, countof(expected_urls));
  free_urlpos(urls);

  char* noise_path = write_temp_file("plain text that should not match");
  assert(noise_path != NULL);
  assert(!wget_recur_file_looks_like_sitemap(noise_path));

  wget_ev_loop_init();
  assert(wget_worker_pool_init(0));
  urls = get_urls_sitemap(sitemap_path, base_url, NULL);
  assert(urls != NULL);
  expect_urls(urls, expected_urls, countof(expected_urls));
  free_urlpos(urls);
  wget_worker_pool_shutdown();
  wget_ev_loop_deinit();

  unlink(sitemap_path);
  unlink(noise_path);
  xfree(sitemap_path);
  xfree(noise_path);
  return 0;
}
