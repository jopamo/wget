/* Minimal gettext stubs used because translations were dropped.
 * src/gettext.h
 */

#ifndef WGET_GETTEXT_H
#define WGET_GETTEXT_H

#include <stddef.h>

static inline char* gettext(const char* msgid) {
  return (char*)msgid;
}

static inline char* ngettext(const char* msgid1, const char* msgid2, unsigned long int n) {
  return (char*)(n == 1 ? msgid1 : msgid2);
}

static inline char* dgettext(const char* domain, const char* msgid) {
  (void)domain;
  return (char*)msgid;
}

static inline char* dngettext(const char* domain, const char* msgid1, const char* msgid2, unsigned long int n) {
  (void)domain;
  return (char*)(n == 1 ? msgid1 : msgid2);
}

static inline char* textdomain(const char* domain) {
  return (char*)domain;
}

static inline char* bindtextdomain(const char* domain, const char* directory) {
  (void)domain;
  return (char*)directory;
}

static inline char* bind_textdomain_codeset(const char* domain, const char* codeset) {
  (void)domain;
  return (char*)codeset;
}

#endif /* WGET_GETTEXT_H */
