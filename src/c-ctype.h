/* Locale independent ctype helpers.
 * src/c-ctype.h
 */

#ifndef WGET_C_CTYPE_H
#define WGET_C_CTYPE_H

#include <ctype.h>

static inline int c_isalnum(int c) {
  return isalnum((unsigned char)c);
}
static inline int c_isalpha(int c) {
  return isalpha((unsigned char)c);
}
static inline int c_isascii(int c) {
  return (unsigned char)c <= 0x7F;
}
static inline int c_iscntrl(int c) {
  return iscntrl((unsigned char)c);
}
static inline int c_isdigit(int c) {
  return isdigit((unsigned char)c);
}
static inline int c_isprint(int c) {
  return isprint((unsigned char)c);
}
static inline int c_isspace(int c) {
  return isspace((unsigned char)c);
}
static inline int c_isupper(int c) {
  return isupper((unsigned char)c);
}
static inline int c_isxdigit(int c) {
  return isxdigit((unsigned char)c);
}
static inline int c_tolower(int c) {
  return tolower((unsigned char)c);
}
static inline int c_toupper(int c) {
  return toupper((unsigned char)c);
}

#endif /* WGET_C_CTYPE_H */
