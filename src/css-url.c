/* Collect URLs from CSS source
 * src/css-url.c
 */

/*
  Note that this is not an actual CSS parser, but just a lexical
  scanner with a tiny bit more smarts bolted on top
  A full parser is somewhat overkill for this job
  The only things we're interested in are @import rules and url() tokens,
  so it's easy enough to grab those without truly understanding the input
  The only downside to this is that we might be coerced into downloading
  files that a browser would ignore
 */

#include "wget.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "css-tokens.h"
#include "css-url.h"
#include "html-url.h"
#include "utils.h"
#include "xstrndup.h"

/* from lex.yy.c */
extern char* yytext;
extern int yyleng;
typedef struct yy_buffer_state* YY_BUFFER_STATE;
extern YY_BUFFER_STATE yy_scan_bytes(const char* bytes, int len);
extern void yy_delete_buffer(YY_BUFFER_STATE b);
extern int yylex(void);
extern void yylex_destroy(void);

static unsigned char to_uchar(char ch) {
  return (unsigned char)ch;
}

/*
  Given a detected URI token, get only the URI specified within
  Also adjust the starting position and length of the string
  A URI can be specified with or without quotes, and the quotes
  can be single or double quotes
  In addition there can be whitespace after the opening parenthesis
  and before the closing parenthesis
*/
static char* get_uri_string(const char* at, int* pos, int* length) {
  /* need at minimum "url()" plus one character inside */
  if (*length < 5)
    return NULL;

  if (strncasecmp(at + *pos, "url(", 4) != 0)
    return NULL;

  *pos += 4;
  *length -= 5; /* drop "url(" and trailing ')' */

  /* skip leading space */
  while (*length > 0 && isspace(to_uchar(at[*pos]))) {
    (*pos)++;
    if (--(*length) == 0)
      return NULL;
  }

  /* skip trailing space */
  while (*length > 0 && isspace(to_uchar(at[*pos + *length - 1]))) {
    (*length)--;
  }

  /* trim off quotes */
  if (*length >= 2 && (at[*pos] == '\'' || at[*pos] == '"')) {
    char quote = at[*pos];
    /* only drop closing quote if it matches */
    if (at[*pos + *length - 1] == quote) {
      (*pos)++;
      *length -= 2;
    }
  }

  if (*length <= 0)
    return NULL;

  return xstrndup(at + *pos, (size_t)*length);
}

void get_urls_css(struct map_context* ctx, int offset, int buf_length) {
  int token;
  int buffer_pos = 0;
  int pos;
  int length;
  char* uri;
  YY_BUFFER_STATE b;

  if (!ctx || !ctx->text || buf_length <= 0)
    return;

  /* tell flex to scan from this buffer */
  b = yy_scan_bytes(ctx->text + offset, buf_length);

  while ((token = yylex()) != CSSEOF) {
    /* @import "foo.css"
       or @import url(foo.css)
    */
    if (token == IMPORT_SYM) {
      do {
        buffer_pos += yyleng;
      } while ((token = yylex()) == S);

      if (token == STRING || token == URI) {
        pos = buffer_pos + offset;
        length = yyleng;

        if (token == URI) {
          uri = get_uri_string(ctx->text, &pos, &length);
        }
        else if (length >= 2) {
          /* cut out quote characters */
          char* dst;
          pos++;       /* account for initial quote in ctx->text */
          length -= 2; /* drop both quotes from logical length */
          uri = xmalloc((size_t)length + 1);
          dst = uri;
          memcpy(dst, yytext + 1, (size_t)length);
          dst[length] = '\0';
        }
        else {
          uri = NULL;
        }

        if (uri) {
          struct urlpos* up = append_url(uri, pos, length, ctx);
          DEBUGP(("Found @import: [%s] at %d [%s]\n", yytext, buffer_pos, uri));

          if (up) {
            up->link_inline_p = 1;
            up->link_css_p = 1;
            up->link_expect_css = 1;
          }

          xfree(uri);
        }
      }
    }
    /* background-image: url(foo.png)
       note that we don't care what property this is actually on
    */
    else if (token == URI) {
      pos = buffer_pos + offset;
      length = yyleng;
      uri = get_uri_string(ctx->text, &pos, &length);

      if (uri) {
        struct urlpos* up = append_url(uri, pos, length, ctx);
        DEBUGP(("Found URI: [%s] at %d [%s]\n", yytext, buffer_pos, uri));
        if (up) {
          up->link_inline_p = 1;
          up->link_css_p = 1;
        }

        xfree(uri);
      }
    }

    buffer_pos += yyleng;
  }

  yy_delete_buffer(b);
  yylex_destroy();

  DEBUGP(("\n"));
}

struct urlpos* get_urls_css_file(const char* file, const char* url) {
  struct file_memory* fm;
  struct map_context ctx;

  /* Load the file */
  fm = wget_read_file(file);
  if (!fm) {
    logprintf(LOG_NOTQUIET, "%s: %s\n", file, strerror(errno));
    return NULL;
  }

  DEBUGP(("Loaded %s (size %s).\n", file, number_to_static_string(fm->length)));

  /* flex uses int for buffer length, guard against overflow */
  if (fm->length > INT_MAX) {
    logprintf(LOG_NOTQUIET, _("%s: CSS file too large to scan (%s bytes)\n"), file, number_to_static_string(fm->length));
    wget_read_file_free(fm);
    return NULL;
  }

  ctx.text = fm->content;
  ctx.head = NULL;
  ctx.base = NULL;
  ctx.parent_base = url ? url : opt.base_href;
  ctx.document_file = file;
  ctx.nofollow = 0;

  get_urls_css(&ctx, 0, (int)fm->length);
  wget_read_file_free(fm);
  return ctx.head;
}
