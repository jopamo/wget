/* Declarations for convert.c
 * src/convert.h
 */

#ifndef CONVERT_H
#define CONVERT_H

#include <stdbool.h>

struct hash_table; /* forward declaration */
struct url;        /* forward declaration */

/* Maps URL -> local file used by link conversion */
extern struct hash_table* dl_url_file_map;

/* Sets of downloaded files used for post-processing link conversion */
extern struct hash_table* downloaded_html_set;
extern struct hash_table* downloaded_css_set;

enum convert_options {
  CO_NOCONVERT = 0,         /* don't convert this URL */
  CO_CONVERT_TO_RELATIVE,   /* convert to relative, e.g. "../../otherdir/foo.gif" */
  CO_CONVERT_BASENAME_ONLY, /* convert the file portion only (basename),
                               leaving the rest of the URL unchanged */
  CO_CONVERT_TO_COMPLETE,   /* convert to absolute, e.g. "http://orighost/somedir/bar.jpg" */
  CO_NULLIFY_BASE           /* change to empty string */
};

/* A structure that defines the whereabouts of a URL
   i.e. its position in an HTML document and how it should be rewritten */

struct urlpos {
  struct url* url;  /* the URL of the link, after it has been merged with the base */
  char* local_name; /* local file to which it was saved (used by convert_links) */

  /* reserved for special links such as <base href="..."> which are
     used when converting links, but ignored when downloading */
  unsigned int ignore_when_downloading : 1;

  /* Information about the original link */

  unsigned int link_relative_p : 1;     /* the link was relative */
  unsigned int link_complete_p : 1;     /* the link was complete (had host name) */
  unsigned int link_base_p : 1;         /* the url came from <base href=...> */
  unsigned int link_inline_p : 1;       /* needed to render the page */
  unsigned int link_css_p : 1;          /* the url came from CSS */
  unsigned int link_noquote_html_p : 1; /* from HTML, but does not need quotes */
  unsigned int link_expect_html : 1;    /* expected to contain HTML */
  unsigned int link_expect_css : 1;     /* expected to contain CSS */

  unsigned int link_refresh_p : 1; /* link was received from
                                      <meta http-equiv=refresh content=...> */
  int refresh_timeout;             /* for reconstructing the refresh */

  /* Conversion requirements */
  enum convert_options convert; /* is conversion required */

  /* URL's position in the buffer */
  int pos;
  int size;

  struct urlpos* next; /* next list element */
};

/* downloaded_file() takes a parameter of this type and returns this type */
typedef enum {
  /* Return enumerators */
  FILE_NOT_ALREADY_DOWNLOADED = 0,

  /* Return / parameter enumerators */
  FILE_DOWNLOADED_NORMALLY,
  FILE_DOWNLOADED_AND_HTML_EXTENSION_ADDED,

  /* Parameter enumerators */
  CHECK_FOR_FILE
} downloaded_file_t;

/* Record or query download bookkeeping for a local file name */
downloaded_file_t downloaded_file(downloaded_file_t mode, const char* file);

/* Register that URL has been downloaded to FILE for link conversion */
void register_download(const char* url, const char* file);

/* Register that FROM has been redirected to TO (TO must be registered) */
void register_redirection(const char* from, const char* to);

/* Register that FILE is an HTML file that has been downloaded */
void register_html(const char* file);

/* Register that FILE is a CSS file that has been downloaded */
void register_css(const char* file);

/* Register that FILE has been deleted and clear its mappings */
void register_delete_file(const char* file);

/* Perform link conversion on all downloaded HTML and CSS files */
void convert_all_links(void);

/* Free HTML entity-quoted string, allocated by html_quote_string */
char* html_quote_string(const char* s);

#if defined DEBUG_MALLOC || defined TESTING
/* Cleanup the data structures associated with link conversion */
void convert_cleanup(void);
#endif

#endif /* CONVERT_H */
