/* HTTP status management.
   Separated from http.c. */

#include "wget.h"
#include "http-stat.h"
#include "xalloc.h"
#include "utils.h"

void free_hstat(struct http_stat* hs) {
  xfree(hs->newloc);
  xfree(hs->remote_time);
  xfree(hs->error);
  xfree(hs->rderrmsg);
  xfree(hs->local_file);
  xfree(hs->orig_file_name);
  xfree(hs->message);
#ifdef HAVE_METALINK
  metalink_delete(hs->metalink);
#endif
}