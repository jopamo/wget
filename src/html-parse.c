/* HTML parser for Wget
 * src/html-parse.c
 *
 * Main entry point: map_html_tags()
 * Scans HTML, decodes entities, and reports tags + attributes to a callback
 */

#include "wget.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "html-parse.h"
#include "utils.h"

/* TODO:
 *
 * - Optional hooks for text between tags (e.g. <style>, <script> bodies)
 * - Small regression test suite for malformed markup cases
 */

/* A pool is a resizable string buffer used to store tag and attribute
 * names and values in one contiguous block
 *
 * taginfo->name and each attr->name/value point into this pool
 * Pool starts on the stack and moves to heap only if it outgrows
 * the initial size
 */

struct pool {
  char* contents; /* current storage */
  int size;       /* total size of contents */
  int tail;       /* next write index */
  bool resized;   /* true if contents was heap-allocated */

  char* orig_contents; /* original storage (usually stack-allocated) */
  int orig_size;       /* original size */
};

/* Initialize the pool with stack storage */

#define POOL_INIT(p, initial_storage, initial_size) \
  do {                                              \
    struct pool* P = (p);                           \
    P->contents = (initial_storage);                \
    P->size = (initial_size);                       \
    P->tail = 0;                                    \
    P->resized = false;                             \
    P->orig_contents = P->contents;                 \
    P->orig_size = P->size;                         \
  } while (0)

/* Grow the pool to fit at least tail + increase bytes */

#define POOL_GROW(p, increase) GROW_ARRAY((p)->contents, (p)->size, (p)->tail + (increase), (p)->resized, char)

/* Append bytes [beg, end) to pool without zero termination */

#define POOL_APPEND(p, beg, end)                        \
  do {                                                  \
    const char* PA_beg = (beg);                         \
    int PA_size = (int)((end) - PA_beg);                \
    POOL_GROW(p, PA_size);                              \
    memcpy((p)->contents + (p)->tail, PA_beg, PA_size); \
    (p)->tail += PA_size;                               \
  } while (0)

/* Append a single character to pool (often used for '\0') */

#define POOL_APPEND_CHR(p, ch)             \
  do {                                     \
    char PAC_char = (ch);                  \
    POOL_GROW(p, 1);                       \
    (p)->contents[(p)->tail++] = PAC_char; \
  } while (0)

/* Drop all contents but keep storage */

#define POOL_REWIND(p) (p)->tail = 0

/* Reset back to original stack storage and free heap if used */

#define POOL_FREE(p)                \
  do {                              \
    struct pool* P = (p);           \
    if (P->resized)                 \
      xfree(P->contents);           \
    P->contents = P->orig_contents; \
    P->size = P->orig_size;         \
    P->tail = 0;                    \
    P->resized = false;             \
  } while (0)

/* GROW_ARRAY base macro used by pool and small stack buffers
 *
 * On first resize it switches from stack storage to heap via malloc+memcpy
 * Further resizes use realloc
 */

#define GROW_ARRAY(basevar, sizevar, needed_size, resized, type)        \
  do {                                                                  \
    long ga_needed_size = (needed_size);                                \
    long ga_newsize = (sizevar);                                        \
    while (ga_newsize < ga_needed_size)                                 \
      ga_newsize <<= 1;                                                 \
    if (ga_newsize != (sizevar)) {                                      \
      if (resized)                                                      \
        basevar = xrealloc(basevar, (size_t)ga_newsize * sizeof(type)); \
      else {                                                            \
        void* ga_new = xmalloc((size_t)ga_newsize * sizeof(type));      \
        memcpy(ga_new, basevar, (size_t)(sizevar) * sizeof(type));      \
        (basevar) = ga_new;                                             \
        resized = true;                                                 \
      }                                                                 \
      (sizevar) = ga_newsize;                                           \
    }                                                                   \
  } while (0)

/* Entity helpers:
 * We only support properly terminated entities like &lt; or &#32;
 */

#define FITS(p, n) (p + (n) == end || (p + (n) < end && !c_isalnum((p)[n])))

#define ENT1(p, c0) (FITS(p, 1) && (p)[0] == (c0))
#define ENT2(p, c0, c1) (FITS(p, 2) && (p)[0] == (c0) && (p)[1] == (c1))
#define ENT3(p, c0, c1, c2) (FITS(p, 3) && (p)[0] == (c0) && (p)[1] == (c1) && (p)[2] == (c2))

/* Advance by inc, optionally skipping a trailing ';' after entity */

#define SKIP_SEMI(p, inc) (p += (inc), (p) < end && *(p) == ';' ? ++(p) : (p))

struct tagstack_item {
  const char* tagname_begin;
  const char* tagname_end;
  const char* contents_begin;
  struct tagstack_item* prev;
  struct tagstack_item* next;
};

static struct tagstack_item* tagstack_push(struct tagstack_item** head, struct tagstack_item** tail) {
  struct tagstack_item* ts = xmalloc(sizeof(struct tagstack_item));
  if (*head == NULL) {
    *head = *tail = ts;
    ts->prev = ts->next = NULL;
  }
  else {
    (*tail)->next = ts;
    ts->prev = *tail;
    *tail = ts;
    ts->next = NULL;
  }

  return ts;
}

/* Remove ts and everything after it from the stack */

static void tagstack_pop(struct tagstack_item** head, struct tagstack_item** tail, struct tagstack_item* ts) {
  if (*head == NULL)
    return;

  if (ts == *tail) {
    if (ts == *head) {
      xfree(ts);
      *head = *tail = NULL;
    }
    else {
      ts->prev->next = NULL;
      *tail = ts->prev;
      xfree(ts);
    }
  }
  else {
    if (ts == *head)
      *head = NULL;

    *tail = ts->prev;
    if (ts->prev)
      ts->prev->next = NULL;

    while (ts) {
      struct tagstack_item* p = ts->next;
      xfree(ts);
      ts = p;
    }
  }
}

static struct tagstack_item* tagstack_find(struct tagstack_item* tail, const char* tagname_begin, const char* tagname_end) {
  int len = (int)(tagname_end - tagname_begin);
  while (tail) {
    if (len == (int)(tail->tagname_end - tail->tagname_begin)) {
      if (strncasecmp(tail->tagname_begin, tagname_begin, (size_t)len) == 0)
        return tail;
    }
    tail = tail->prev;
  }
  return NULL;
}

/* Decode HTML character entity starting at *ptr (after '&'), within [*ptr, end)
 *
 * Returns decoded ASCII value and advances *ptr past entity or
 * returns -1 on failure and leaves *ptr unchanged
 *
 * Supports:
 *   - numeric: &#DDD; and &#xHH;
 *   - named:  &lt, &gt, &amp, &apos, &quot
 */

static int decode_entity(const char** ptr, const char* end) {
  const char* p = *ptr;
  int value = -1;

  if (++p == end)
    return -1;

  switch (*p++) {
    case '#': {
      /* numeric entities in decimal or hex form */
      int digits = 0;
      value = 0;
      if (*p == 'x') {
        for (++p; value < 256 && p < end && c_isxdigit(*p); p++, digits++)
          value = (value << 4) + _unhex(*p);
      }
      else {
        for (; value < 256 && p < end && c_isdigit(*p); p++, digits++)
          value = (value * 10) + (*p - '0');
      }
      if (!digits)
        return -1;
      /* 7-bit safe only; ignore NUL and high codes we can't reinsert */
      if (!value || (value & ~0x7f))
        return -1;
      *ptr = SKIP_SEMI(p, 0);
      return value;
    }
    case 'g':
      if (ENT1(p, 't'))
        value = '>', *ptr = SKIP_SEMI(p, 1);
      break;
    case 'l':
      if (ENT1(p, 't'))
        value = '<', *ptr = SKIP_SEMI(p, 1);
      break;
    case 'a':
      if (ENT2(p, 'm', 'p'))
        value = '&', *ptr = SKIP_SEMI(p, 2);
      else if (ENT3(p, 'p', 'o', 's'))
        value = '\'', *ptr = SKIP_SEMI(p, 3);
      break;
    case 'q':
      if (ENT3(p, 'u', 'o', 't'))
        value = '\"', *ptr = SKIP_SEMI(p, 3);
      break;
  }
  return value;
}

#undef ENT1
#undef ENT2
#undef ENT3
#undef FITS
#undef SKIP_SEMI

enum { AP_DOWNCASE = 1, AP_DECODE_ENTITIES = 2, AP_TRIM_BLANKS = 4 };

/* Copy [beg, end) into pool, applying transformations from flags:
 *
 * AP_DOWNCASE         lower-case all letters
 * AP_DECODE_ENTITIES  decode HTML entities into ASCII
 * AP_TRIM_BLANKS      trim leading/trailing blanks and squash newlines
 */

static void convert_and_copy(struct pool* pool, const char* beg, const char* end, int flags) {
  int old_tail = pool->tail;

  if (flags & AP_TRIM_BLANKS) {
    while (beg < end && c_isspace(*beg))
      ++beg;
    while (end > beg && c_isspace(end[-1]))
      --end;
  }

  if (flags & AP_DECODE_ENTITIES) {
    const char* from = beg;
    char* to;
    bool squash_newlines = (flags & AP_TRIM_BLANKS) != 0;

    POOL_GROW(pool, (int)(end - beg));
    to = pool->contents + pool->tail;

    while (from < end) {
      if (*from == '&') {
        int entity = decode_entity(&from, end);
        if (entity != -1)
          *to++ = (char)entity;
        else
          *to++ = *from++;
      }
      else if ((*from == '\n' || *from == '\r') && squash_newlines)
        ++from;
      else
        *to++ = *from++;
    }

    assert(to - (pool->contents + pool->tail) <= end - beg);

    pool->tail = (int)(to - pool->contents);
    POOL_APPEND_CHR(pool, '\0');
  }
  else {
    POOL_APPEND(pool, beg, end);
    POOL_APPEND_CHR(pool, '\0');
  }

  if (flags & AP_DOWNCASE) {
    char* p = pool->contents + old_tail;
    for (; *p; p++)
      *p = c_tolower(*p);
  }
}

/* Tag and attribute names:
 *
 * Historically only [A-Za-z0-9.-] were allowed, but real pages use
 * many vendor-specific names
 *
 * We now allow any printable 7-bit char except:
 *   whitespace, control chars, '=', '<', '>', '/'
 */

#define NAME_CHAR_P(x) ((x) > 32 && (x) < 127 && (x) != '=' && (x) != '<' && (x) != '>' && (x) != '/')

/* Skip an SGML declaration like <!DOCTYPE ...> or other <! ... > blocks
 *
 * In strict comment mode this is also used to skip comments;
 * it tries to handle quotes and nested comment markers conservatively
 */

static const char* advance_declaration(const char* beg, const char* end) {
  const char* p = beg;
  char quote_char = '\0';
  char ch;

  enum { AC_S_DONE, AC_S_BACKOUT, AC_S_BANG, AC_S_DEFAULT, AC_S_DCLNAME, AC_S_DASH1, AC_S_DASH2, AC_S_COMMENT, AC_S_DASH3, AC_S_DASH4, AC_S_QUOTE1, AC_S_IN_QUOTE, AC_S_QUOTE2 } state = AC_S_BANG;

  if (beg == end)
    return beg;
  ch = *p++;

  while (state != AC_S_DONE && state != AC_S_BACKOUT) {
    if (p == end)
      state = AC_S_BACKOUT;
    switch (state) {
      case AC_S_DONE:
      case AC_S_BACKOUT:
        break;
      case AC_S_BANG:
        if (ch == '!') {
          ch = *p++;
          state = AC_S_DEFAULT;
        }
        else
          state = AC_S_BACKOUT;
        break;
      case AC_S_DEFAULT:
        switch (ch) {
          case '-':
            state = AC_S_DASH1;
            break;
          case ' ':
          case '\t':
          case '\r':
          case '\n':
            ch = *p++;
            break;
          case '<':
          case '>':
            state = AC_S_DONE;
            break;
          case '\'':
          case '\"':
            state = AC_S_QUOTE1;
            break;
          default:
            if (NAME_CHAR_P(ch))
              state = AC_S_DCLNAME;
            else
              state = AC_S_BACKOUT;
            break;
        }
        break;
      case AC_S_DCLNAME:
        if (ch == '-')
          state = AC_S_DASH1;
        else if (NAME_CHAR_P(ch))
          ch = *p++;
        else
          state = AC_S_DEFAULT;
        break;
      case AC_S_QUOTE1:
        assert(ch == '\'' || ch == 0x22);
        quote_char = ch;
        ch = *p++;
        state = AC_S_IN_QUOTE;
        break;
      case AC_S_IN_QUOTE:
        if (ch == quote_char)
          state = AC_S_QUOTE2;
        else
          ch = *p++;
        break;
      case AC_S_QUOTE2:
        assert(ch == quote_char);
        ch = *p++;
        state = AC_S_DEFAULT;
        break;
      case AC_S_DASH1:
        assert(ch == '-');
        ch = *p++;
        state = AC_S_DASH2;
        break;
      case AC_S_DASH2:
        switch (ch) {
          case '-':
            ch = *p++;
            state = AC_S_COMMENT;
            break;
          default:
            state = AC_S_BACKOUT;
        }
        break;
      case AC_S_COMMENT:
        switch (ch) {
          case '-':
            state = AC_S_DASH3;
            break;
          default:
            ch = *p++;
            break;
        }
        break;
      case AC_S_DASH3:
        assert(ch == '-');
        ch = *p++;
        state = AC_S_DASH4;
        break;
      case AC_S_DASH4:
        switch (ch) {
          case '-':
            ch = *p++;
            state = AC_S_DEFAULT;
            break;
          default:
            state = AC_S_COMMENT;
            break;
        }
        break;
    }
  }

  if (state == AC_S_BACKOUT)
    return beg + 1;
  return p;
}

/* Find "-->" between [beg, end), return pointer past terminator or NULL */

static const char* find_comment_end(const char* beg, const char* end) {
  const char* p = beg - 1;

  while ((p += 3) < end)
    switch (p[0]) {
      case '>':
        if (p[-1] == '-' && p[-2] == '-')
          return p + 1;
        break;
      case '-':
      at_dash:
        if (p[-1] == '-') {
        at_dash_dash:
          if (++p == end)
            return NULL;
          switch (p[0]) {
            case '>':
              return p + 1;
            case '-':
              goto at_dash_dash;
          }
        }
        else {
          if ((p += 2) >= end)
            return NULL;
          switch (p[0]) {
            case '>':
              if (p[-1] == '-')
                return p + 1;
              break;
            case '-':
              goto at_dash;
          }
        }
    }
  return NULL;
}

/* Return true if name [b, e) exists in hash table ht
 * If ht is NULL, all names are accepted
 */

static bool name_allowed(const struct hash_table* ht, const char* b, const char* e) {
  char buf[256], *copy;
  size_t len = (size_t)(e - b);
  bool ret;

  if (!ht)
    return true;

  if (len < sizeof(buf))
    copy = buf;
  else
    copy = xmalloc(len + 1);

  memcpy(copy, b, len);
  copy[len] = 0;

  ret = hash_table_get(ht, copy) != NULL;

  if (copy != buf)
    xfree(copy);

  return ret;
}

/* Advance p by one byte, or bail out to finish if out of bounds */

#define ADVANCE(p)  \
  do {              \
    ++(p);          \
    if ((p) >= end) \
      goto finish;  \
  } while (0)

/* Skip ASCII whitespace */

#define SKIP_WS(p)            \
  do {                        \
    while (c_isspace(*(p))) { \
      ADVANCE(p);             \
    }                         \
  } while (0)

/* Core HTML scanner:
 *
 *   - walks text looking for '<...>' regions
 *   - parses tag names and attributes
 *   - decodes attribute values depending on flags
 *   - reports each tag to mapfun
 *
 * allowed_tags and allowed_attributes are optional hash filters to
 * avoid copying tags/attributes the caller does not care about
 */

void map_html_tags(const char* text, int size, void (*mapfun)(struct taginfo*, void*), void* maparg, int flags, const struct hash_table* allowed_tags, const struct hash_table* allowed_attributes) {
  char pool_initial_storage[256];
  struct pool pool;

  const char* p = text;
  const char* end = text + size;

  struct attr_pair attr_pair_initial_storage[8];
  int attr_pair_size = (int)countof(attr_pair_initial_storage);
  bool attr_pair_resized = false;
  struct attr_pair* pairs = attr_pair_initial_storage;

  struct tagstack_item* head = NULL;
  struct tagstack_item* tail = NULL;

  if (!size)
    return;

  POOL_INIT(&pool, pool_initial_storage, (int)countof(pool_initial_storage));

  {
    int nattrs;
    bool end_tag;
    const char *tag_name_begin, *tag_name_end;
    const char* tag_start_position;
    bool uninteresting_tag;

  look_for_tag:
    POOL_REWIND(&pool);

    nattrs = 0;
    end_tag = false;

    /* find '<' quickly, then parse from there */
    p = memchr(p, '<', (size_t)(end - p));
    if (!p)
      goto finish;

    tag_start_position = p;
    ADVANCE(p);

    /* classify tag: declaration, end-tag, or start-tag */
    if (*p == '!') {
      if (!(flags & MHT_STRICT_COMMENTS) && p + 3 < end && p[1] == '-' && p[2] == '-') {
        const char* comment_end = find_comment_end(p + 3, end);
        if (comment_end)
          p = comment_end;
      }
      else {
        p = advance_declaration(p, end);
      }
      if (p == end)
        goto finish;
      goto look_for_tag;
    }
    else if (*p == '/') {
      end_tag = true;
      ADVANCE(p);
    }

    tag_name_begin = p;
    while (NAME_CHAR_P(*p))
      ADVANCE(p);
    if (p == tag_name_begin)
      goto look_for_tag;
    tag_name_end = p;
    SKIP_WS(p);

    if (!end_tag) {
      struct tagstack_item* ts = tagstack_push(&head, &tail);
      if (ts) {
        ts->tagname_begin = tag_name_begin;
        ts->tagname_end = tag_name_end;
        ts->contents_begin = NULL;
      }
    }

    if (end_tag && *p != '>' && *p != '<')
      goto backout_tag;

    if (!name_allowed(allowed_tags, tag_name_begin, tag_name_end))
      uninteresting_tag = true;
    else {
      uninteresting_tag = false;
      convert_and_copy(&pool, tag_name_begin, tag_name_end, AP_DOWNCASE);
    }

    /* attribute loop */
    while (1) {
      const char *attr_name_begin, *attr_name_end;
      const char *attr_value_begin, *attr_value_end;
      const char *attr_raw_value_begin, *attr_raw_value_end;
      int operation = AP_DOWNCASE;

      SKIP_WS(p);

      if (*p == '/') {
        /* XML-style self-closing tags: <foo a=b /> */
        ADVANCE(p);
        SKIP_WS(p);
        if (*p != '<' && *p != '>')
          goto backout_tag;
      }

      if (*p == '<' || *p == '>')
        break;

      attr_name_begin = p;
      while (NAME_CHAR_P(*p))
        ADVANCE(p);
      attr_name_end = p;
      if (attr_name_begin == attr_name_end)
        goto backout_tag;

      SKIP_WS(p);

      if (NAME_CHAR_P(*p) || *p == '/' || *p == '<' || *p == '>') {
        /* minimized attributes like <ul compact> */
        attr_raw_value_begin = attr_value_begin = attr_name_begin;
        attr_raw_value_end = attr_value_end = attr_name_end;
      }
      else if (*p == '=') {
        ADVANCE(p);
        SKIP_WS(p);
        if (*p == '\"' || *p == '\'') {
          bool newline_seen = false;
          char quote_char = *p;
          attr_raw_value_begin = p;
          ADVANCE(p);
          attr_value_begin = p;

          while (*p != quote_char) {
            if (!newline_seen && *p == '\n') {
              /* heuristic for missing closing quote */
              p = attr_value_begin;
              newline_seen = true;
              continue;
            }
            else if (newline_seen && (*p == '<' || *p == '>'))
              break;
            ADVANCE(p);
          }
          attr_value_end = p;
          if (*p == quote_char)
            ADVANCE(p);
          else
            goto look_for_tag;
          attr_raw_value_end = p;
          operation = AP_DECODE_ENTITIES;
          if (flags & MHT_TRIM_VALUES)
            operation |= AP_TRIM_BLANKS;
        }
        else {
          attr_value_begin = p;
          while (!c_isspace(*p) && *p != '<' && *p != '>')
            ADVANCE(p);
          attr_value_end = p;
          if (attr_value_begin == attr_value_end)
            goto backout_tag;
          attr_raw_value_begin = attr_value_begin;
          attr_raw_value_end = attr_value_end;
          operation = AP_DECODE_ENTITIES;
        }
      }
      else {
        goto backout_tag;
      }

      if (uninteresting_tag)
        continue;

      if (!name_allowed(allowed_attributes, attr_name_begin, attr_name_end))
        continue;

      GROW_ARRAY(pairs, attr_pair_size, nattrs + 1, attr_pair_resized, struct attr_pair);

      pairs[nattrs].name_pool_index = pool.tail;
      convert_and_copy(&pool, attr_name_begin, attr_name_end, AP_DOWNCASE);

      pairs[nattrs].value_pool_index = pool.tail;
      convert_and_copy(&pool, attr_value_begin, attr_value_end, operation);
      pairs[nattrs].value_raw_beginning = attr_raw_value_begin;
      pairs[nattrs].value_raw_size = (int)(attr_raw_value_end - attr_raw_value_begin);
      ++nattrs;
    }

    if (!end_tag && tail && (tail->tagname_begin == tag_name_begin))
      tail->contents_begin = p + 1;

    if (uninteresting_tag) {
      ADVANCE(p);
      goto look_for_tag;
    }

    /* build taginfo and invoke callback */
    {
      int i;
      struct taginfo taginfo;
      struct tagstack_item* ts = NULL;

      taginfo.name = pool.contents;
      taginfo.end_tag_p = end_tag ? 1 : 0;
      taginfo.nattrs = nattrs;

      for (i = 0; i < nattrs; i++) {
        pairs[i].name = pool.contents + pairs[i].name_pool_index;
        pairs[i].value = pool.contents + pairs[i].value_pool_index;
      }

      taginfo.attrs = pairs;
      taginfo.start_position = tag_start_position;
      taginfo.end_position = p + 1;
      taginfo.contents_begin = NULL;
      taginfo.contents_end = NULL;

      if (end_tag) {
        ts = tagstack_find(tail, tag_name_begin, tag_name_end);
        if (ts) {
          if (ts->contents_begin) {
            taginfo.contents_begin = ts->contents_begin;
            taginfo.contents_end = tag_start_position;
          }
          tagstack_pop(&head, &tail, ts);
        }
      }

      mapfun(&taginfo, maparg);
      if (*p != '<')
        ADVANCE(p);
    }
    goto look_for_tag;

  backout_tag:
    /* not a real tag; treat '<' as data and continue */
    p = tag_start_position + 1;
    goto look_for_tag;
  }

finish:
  POOL_FREE(&pool);
  if (attr_pair_resized)
    xfree(pairs);
  tagstack_pop(&head, &tail, head);
}

#undef ADVANCE
#undef SKIP_WS
#undef NAME_CHAR_P
