/* Read and parse the .netrc file to get hosts, accounts, and passwords
 * src/netrc.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "netrc.h"
#include "init.h"

#define NETRC_FILE_NAME ".netrc"

typedef struct _acc_t {
  /* NULL host means default machine entry */
  char* host;
  char* acc;
  /* NULL password means no password */
  char* passwd;
  struct _acc_t* next;
} acc_t;

static acc_t* parse_netrc(const char*);
static acc_t* parse_netrc_fp(const char*, FILE*);

static acc_t* netrc_list;
static bool processed_netrc;

#if defined DEBUG_MALLOC || defined TESTING
static void free_netrc(acc_t*);

void netrc_cleanup(void) {
  free_netrc(netrc_list);
  netrc_list = NULL;
  processed_netrc = false;
}
#endif

/* Return the user and password given host, user, and password from URL
   May update *acc and *passwd in place
   If slack_default is nonzero, a default entry is allowed as a fallback */
void search_netrc(const char* host, const char** acc, const char** passwd, int slack_default, FILE* fp_netrc) {
  acc_t* l;

  if (!opt.netrc)
    return;

  if (!processed_netrc) {
    netrc_list = NULL;
    processed_netrc = true;

    if (fp_netrc) {
      netrc_list = parse_netrc_fp(NETRC_FILE_NAME, fp_netrc);
    }
    else if (opt.homedir) {
      file_stats_t fstats;
      char* path = ajoin_dir_file(opt.homedir, NETRC_FILE_NAME);

      if (file_exists_p(path, &fstats))
        netrc_list = parse_netrc(path);

      xfree(path);
    }
  }

  if (!netrc_list)
    return;

  /* Both account and password already provided */
  if (*acc && *passwd)
    return;

  /* Try host specific entry first */
  for (l = netrc_list; l; l = l->next) {
    if (!l->host)
      continue;
    if (!strcasecmp(l->host, host))
      break;
  }

  if (l) {
    if (*acc) {
      /* Only password is missing and the username must match */
      if (!strcmp(l->acc, *acc))
        *passwd = l->passwd;
      else
        *passwd = NULL;
    }
    else {
      /* Username from netrc, optional password from netrc */
      *acc = l->acc;
      if (l->passwd)
        *passwd = l->passwd;
    }
    return;
  }

  /* No host specific entry, maybe allow default */
  if (!slack_default)
    return;
  if (*acc)
    return;

  for (l = netrc_list; l; l = l->next)
    if (!l->host)
      break;

  if (!l)
    return;

  *acc = l->acc;
  if (!*passwd)
    *passwd = l->passwd;
}

/* Maybe add NEWENTRY to the account list LIST
   NEWENTRY is always replaced with a fresh zeroed acc_t for reuse */
static void maybe_add_to_list(acc_t** newentry, acc_t** list) {
  acc_t* a = *newentry;
  acc_t* l = *list;

  /* Require an account name before adding to list */
  if (a && !a->acc) {
    xfree(a->host);
    xfree(a->acc);
    xfree(a->passwd);
  }
  else {
    if (a) {
      a->next = l;
      l = a;
    }

    a = xmalloc(sizeof(acc_t));
  }

  memset(a, 0, sizeof(*a));

  *newentry = a;
  *list = l;
}

/* Shift contents of a NUL terminated string one char to the left
   Used to process backslash and quote constructs in the netrc file */
static void shift_left(char* string) {
  char* p;

  for (p = string; *p; ++p)
    *p = *(p + 1);
}

/* Parse a .netrc file (as described in the ftp(1) manual page) */
static acc_t* parse_netrc_fp(const char* path, FILE* fp) {
  char *line = NULL, *p, *tok;
  const char* premature_token = NULL;
  acc_t *current = NULL, *retval = NULL;
  int ln = 0;
  int qmark;
  size_t bufsize = 0;

  enum { tok_nothing, tok_account, tok_login, tok_macdef, tok_machine, tok_password, tok_port, tok_force } last_token = tok_nothing;

  while (getline(&line, &bufsize, fp) > 0) {
    ln++;

    p = line;
    qmark = 0;

    while (*p && c_isspace(*p))
      p++;

    if (last_token == tok_macdef && !*p)
      last_token = tok_nothing;

    while (*p && last_token != tok_macdef) {
      while (*p && c_isspace(*p))
        p++;

      if (*p == '#' || !*p)
        break;

      if (*p == '"') {
        qmark = 1;
        shift_left(p);
      }

      tok = p;

      while (*p && (qmark ? *p != '"' : !c_isspace(*p))) {
        if (*p == '\\')
          shift_left(p);
        p++;
      }

      if (qmark) {
        shift_left(p);
        qmark = 0;
      }

      if (*p)
        *p++ = '\0';

      switch (last_token) {
        case tok_login:
          if (current) {
            xfree(current->acc);
            current->acc = xstrdup(tok);
          }
          else
            premature_token = "login";
          break;

        case tok_machine:
          maybe_add_to_list(&current, &retval);
          current->host = xstrdup(tok);
          break;

        case tok_password:
          if (current) {
            xfree(current->passwd);
            current->passwd = xstrdup(tok);
          }
          else
            premature_token = "password";
          break;

        case tok_macdef:
          if (!current)
            premature_token = "macdef";
          break;

        case tok_account:
          if (!current)
            premature_token = "account";
          break;

        case tok_port:
          if (!current)
            premature_token = "port";
          break;

        case tok_force:
          if (!current)
            premature_token = "force";
          break;

        case tok_nothing:
          break;
      }

      if (premature_token) {
        fprintf(stderr, _("%s: %s:%d: warning: %s token appears before any machine name\n"), exec_name, path, ln, quote(premature_token));
        premature_token = NULL;
      }

      if (last_token != tok_nothing) {
        last_token = tok_nothing;
      }
      else {
        if (!strcmp(tok, "account"))
          last_token = tok_account;

        else if (!strcmp(tok, "default"))
          maybe_add_to_list(&current, &retval);

        else if (!strcmp(tok, "login") || !strcmp(tok, "user"))
          last_token = tok_login;

        else if (!strcmp(tok, "macdef"))
          last_token = tok_macdef;

        else if (!strcmp(tok, "machine"))
          last_token = tok_machine;

        else if (!strcmp(tok, "password") || !strcmp(tok, "passwd"))
          last_token = tok_password;

        else if (!strcmp(tok, "port"))
          last_token = tok_port;

        else if (!strcmp(tok, "force"))
          last_token = tok_force;

        else
          fprintf(stderr, _("%s: %s:%d: unknown token \"%s\"\n"), exec_name, path, ln, tok);
      }
    }
  }

  xfree(line);

  /* Finalize last machine entry, if any */
  maybe_add_to_list(&current, &retval);
  xfree(current);

  /* Reverse to restore file order */
  current = retval;
  retval = NULL;
  while (current) {
    acc_t* saved_reference = current->next;
    current->next = retval;
    retval = current;
    current = saved_reference;
  }

  return retval;
}

static acc_t* parse_netrc(const char* path) {
  FILE* fp = fopen(path, "r");
  acc_t* acc;

  if (!fp) {
    fprintf(stderr, _("%s: Cannot read %s (%s).\n"), exec_name, path, strerror(errno));
    return NULL;
  }

  acc = parse_netrc_fp(path, fp);
  fclose(fp);

  return acc;
}

#if defined DEBUG_MALLOC || defined TESTING
static void free_netrc(acc_t* l) {
  acc_t* t;

  while (l) {
    t = l->next;
    xfree(l->acc);
    xfree(l->passwd);
    xfree(l->host);
    xfree(l);
    l = t;
  }
}
#endif

#ifdef TESTING
#include "../tests/unit-tests.h"

const char* test_parse_netrc(void) {
#ifdef HAVE_FMEMOPEN
  static const struct test {
    const char* pw_in;
    const char* pw_expected;
  } tests[] = {
      {"a\\b", "ab"},   {"a\\\\b", "a\\b"},   {"\"a\\\\b\"", "a\\b"}, {"\"a\\\"b\"", "a\"b"}, {"a\"b", "a\"b"}, {"a\\\\\\\\b", "a\\\\b"},
      {"a\\\\", "a\\"}, {"\"a\\\\\"", "a\\"}, {"a\\", "a"},           {"\"a b\"", "a b"},     {"a b", "a"},
  };
  unsigned i;
  static char errmsg[128];

  for (i = 0; i < countof(tests); ++i) {
    const struct test* t = &tests[i];
    char netrc[128];
    FILE* fp;
    acc_t* acc;
    int n;

    n = snprintf(netrc, sizeof(netrc), "machine localhost\n\tlogin me\n\tpassword %s", t->pw_in);
    mu_assert("test_parse_netrc: failed to fmemopen() netrc", (fp = fmemopen(netrc, n, "r")) != NULL);

    acc = parse_netrc_fp("memory", fp);
    fclose(fp);

    if (strcmp(acc->passwd, t->pw_expected)) {
      snprintf(errmsg, sizeof(errmsg), "test_parse_netrc: wrong result [%u]. Expected '%s', got '%s'", i, t->pw_expected, acc->passwd);
      free_netrc(acc);
      return errmsg;
    }

    free_netrc(acc);
  }

#endif /* HAVE_FMEMOPEN */
  return NULL;
}
#endif /* TESTING */
