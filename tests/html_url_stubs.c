/* Minimal helpers needed by the sitemap parser tests. */

#include "wget.h"

#include "html-url.h"
#include "url.h"
#include "exits.h"

struct iri dummy_iri;

void inform_exit_status(uerr_t err WGET_ATTR_UNUSED) {}

void free_urlpos(struct urlpos* list) {
  while (list) {
    struct urlpos* next = list->next;
    if (list->url)
      url_free(list->url);
    xfree(list->local_name);
    xfree(list);
    list = next;
  }
}
