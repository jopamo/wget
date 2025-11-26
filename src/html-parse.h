/* Declarations for html-parse.c
 * src/html-parse.h
 */

#ifndef HTML_PARSE_H
#define HTML_PARSE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct attr_pair {
  char* name;   /* attribute name */
  char* value;  /* decoded attribute value */

  /* original value slice in input, including quotes if present */
  const char* value_raw_beginning;
  int value_raw_size;

  /* internal indexes into the string pool used by the parser */
  int name_pool_index;
  int value_pool_index;
};

struct taginfo {
  char* name;              /* tag name, lowercased */
  int end_tag_p;           /* nonzero for </tag> */

  int nattrs;              /* number of attributes */
  struct attr_pair* attrs; /* attribute array */

  const char* start_position; /* first character of tag, including '<' */
  const char* end_position;   /* first character after closing '>' */

  /* text region between matching start and end tags, if known */
  const char* contents_begin;
  const char* contents_end;
};

struct hash_table; /* forward declaration */

/* Flags for map_html_tags */
#define MHT_STRICT_COMMENTS 1 /* honor SGML-style comment rules */
#define MHT_TRIM_VALUES 2     /* trim attribute values and squash wrapped newlines */

/* Scan HTML buffer and invoke mapfun for each tag encountered
 *
 * text,size        input buffer
 * mapfun,maparg    callback and user data
 * flags            MHT_* flags controlling parsing behavior
 * allowed_tags     optional tag-name allowlist (NULL for all)
 * allowed_attrs    optional attribute-name allowlist (NULL for all)
 */
void map_html_tags(const char* text,
                   int size,
                   void (*mapfun)(struct taginfo* tag, void* arg),
                   void* maparg,
                   int flags,
                   const struct hash_table* allowed_tags,
                   const struct hash_table* allowed_attrs);

#ifdef __cplusplus
}
#endif

#endif /* HTML_PARSE_H */
