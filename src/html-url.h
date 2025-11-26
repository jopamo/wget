/* Declarations for html-url.c
 * src/html-url.h
 */

#ifndef HTML_URL_H
#define HTML_URL_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct urlpos;
struct file_memory;
struct iri;

/* parsing state for a single HTML document */
struct map_context {
  const char* text;          /* HTML source buffer */
  char* base;                /* active <base href=...> URL, owned by context */
  const char* parent_base;   /* caller supplied base URL when no <base> is present */
  const char* document_file; /* file name used for logging and diagnostics */
  bool nofollow;             /* true if <meta name=robots content=...> says nofollow */

  struct urlpos* head; /* head of linked list of discovered URLs */
};

struct urlpos* get_urls_file(const char* file, bool* read_again);
struct urlpos* get_urls_html(const char* file, const char* url, bool* meta_disallow_follow, struct iri* iri);
struct urlpos* get_urls_html_fm(const char* file, const struct file_memory* fm, const char* url, bool* meta_disallow_follow, struct iri* iri);
struct urlpos* append_url(const char* link_uri, int position, int size, struct map_context* ctx);
void free_urlpos(struct urlpos* head);

#if defined DEBUG_MALLOC || defined TESTING
void cleanup_html_url(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HTML_URL_H */
