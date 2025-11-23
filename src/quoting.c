/* Quoting helpers that mimic the bits of gnulib used by Wget.
 * src/quoting.c
 */

#include "wget.h"
#include "quote.h"
#include "quotearg.h"
#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define QUOTE_SLOTS 8

static char* quote_slots[QUOTE_SLOTS];

static void free_slots(void) {
  for (int i = 0; i < QUOTE_SLOTS; ++i) {
    xfree(quote_slots[i]);
  }
}

static bool is_printable(unsigned char c) {
  return c >= 0x20 && c < 0x7F;
}

static size_t escaped_length(const char* arg, bool escape) {
  if (!arg)
    return escape ? 2 : 0;

  size_t len = escape ? 2 : 0;
  for (const unsigned char* p = (const unsigned char*)arg; *p; ++p) {
    if (!escape) {
      ++len;
      continue;
    }

    switch (*p) {
      case '\\':
      case '"':
        len += 2;
        break;
      case '\n':
      case '\r':
      case '\t':
      case '\f':
      case '\v':
        len += 2;
        break;
      default:
        len += is_printable(*p) ? 1 : 4;
        break;
    }
  }
  return len;
}

static void write_escape(char** cursor, unsigned char c) {
  switch (c) {
    case '\\':
    case '"':
      *(*cursor)++ = '\\';
      *(*cursor)++ = (char)c;
      break;
    case '\n':
      *(*cursor)++ = '\\';
      *(*cursor)++ = 'n';
      break;
    case '\r':
      *(*cursor)++ = '\\';
      *(*cursor)++ = 'r';
      break;
    case '\t':
      *(*cursor)++ = '\\';
      *(*cursor)++ = 't';
      break;
    case '\f':
      *(*cursor)++ = '\\';
      *(*cursor)++ = 'f';
      break;
    case '\v':
      *(*cursor)++ = '\\';
      *(*cursor)++ = 'v';
      break;
    default:
      if (is_printable(c)) {
        *(*cursor)++ = (char)c;
      }
      else {
        sprintf(*cursor, "\\x%02x", c);
        *cursor += 4;
      }
      break;
  }
}

static const char* format_argument(enum quoting_style style, const char* arg, int slot_index) {
  if (slot_index < 0)
    slot_index = 0;
  slot_index %= QUOTE_SLOTS;

  bool escape = style == escape_quoting_style;
  size_t len = escaped_length(arg, escape);
  char* buffer = quote_slots[slot_index];
  buffer = xrealloc(buffer, len + 1);
  quote_slots[slot_index] = buffer;

  char* cursor = buffer;
  if (escape)
    *cursor++ = '"';
  if (arg) {
    if (escape) {
      for (const unsigned char* p = (const unsigned char*)arg; *p; ++p)
        write_escape(&cursor, *p);
    }
    else {
      strcpy(cursor, arg);
      cursor += strlen(arg);
    }
  }
  if (escape)
    *cursor++ = '"';
  *cursor = '\0';
  return buffer;
}

const char* quote(const char* arg) {
  return quotearg_style(escape_quoting_style, arg);
}

const char* quote_n(int n, const char* arg) {
  return quotearg_n_style(n, escape_quoting_style, arg);
}

const char* quotearg_style(enum quoting_style style, const char* arg) {
  static int next_slot;
  const char* res = format_argument(style, arg, next_slot);
  next_slot = (next_slot + 1) % QUOTE_SLOTS;
  return res;
}

const char* quotearg_n_style(int n, enum quoting_style style, const char* arg) {
  return format_argument(style, arg, n);
}

void quotearg_free(void) {
  free_slots();
}
