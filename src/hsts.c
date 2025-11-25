/* HTTP Strict Transport Security (HSTS) support
 * src/hsts.c
 */

#include "wget.h"

#ifdef HAVE_HSTS
#include "hsts.h"
#include "utils.h"
#include "host.h" /* is_valid_ip_address */
#include "hash.h"
#include "c-ctype.h"
#include "threading.h"
#ifdef TESTING
#include "init.h" /* ajoin_dir_file */
#include "../tests/unit-tests.h"
#endif

#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <sys/file.h>

struct hsts_store {
  struct hash_table* table;
  time_t last_mtime;
  bool changed;
  wget_mutex_t lock;
};

static void hsts_lock(hsts_store_t store) {
  wget_mutex_lock(&store->lock);
}

static void hsts_unlock(hsts_store_t store) {
  wget_mutex_unlock(&store->lock);
}

struct hsts_kh {
  char* host;
  int explicit_port;
};

struct hsts_kh_info {
  int64_t created;
  int64_t max_age;
  bool include_subdomains;
};

enum hsts_kh_match { NO_MATCH, SUPERDOMAIN_MATCH, CONGRUENT_MATCH };

#define hsts_is_host_name_valid(host) (!is_valid_ip_address(host))
#define hsts_is_scheme_valid(scheme) (scheme == SCHEME_HTTPS)
#define hsts_is_host_eligible(scheme, host) (hsts_is_scheme_valid(scheme) && hsts_is_host_name_valid(host))

#define DEFAULT_HTTP_PORT 80
#define DEFAULT_SSL_PORT 443
#define MAKE_EXPLICIT_PORT(s, p) (s == SCHEME_HTTPS ? (p == DEFAULT_SSL_PORT ? 0 : (p)) : (p == DEFAULT_HTTP_PORT ? 0 : (p)))

/* Hashing and comparison functions for the hash table */

#ifdef __clang__
__attribute__((no_sanitize("integer")))
#endif
static unsigned long hsts_hash_func(const void* key) {
  const struct hsts_kh* k = (const struct hsts_kh*)key;
  const unsigned char* h = (const unsigned char*)k->host;
  unsigned long hash = (unsigned long)k->explicit_port;

  while (*h) {
    hash = hash * 31u + *h;
    ++h;
  }

  return hash;
}

static int hsts_cmp_func(const void* h1, const void* h2) {
  const struct hsts_kh* kh1 = (const struct hsts_kh*)h1;
  const struct hsts_kh* kh2 = (const struct hsts_kh*)h2;

  return (!strcmp(kh1->host, kh2->host)) && (kh1->explicit_port == kh2->explicit_port);
}

/* Private functions */

static struct hsts_kh_info* hsts_find_entry(hsts_store_t store, const char* host, int explicit_port, enum hsts_kh_match* match_type, struct hsts_kh* kh) {
  struct hsts_kh* k = xnew(struct hsts_kh);
  struct hsts_kh_info* khi = NULL;
  enum hsts_kh_match match = NO_MATCH;
  char* org_ptr;

  k->host = xstrdup_lower(host);
  k->explicit_port = explicit_port;

  /* keep original pointer so substring matching does not break free */
  org_ptr = k->host;

  khi = (struct hsts_kh_info*)hash_table_get(store->table, k);
  if (khi) {
    match = CONGRUENT_MATCH;
    goto end;
  }

  for (char* p = k->host; (p = strchr(p, '.'));) {
    k->host = ++p;
    khi = (struct hsts_kh_info*)hash_table_get(store->table, k);
    if (khi && khi->include_subdomains) {
      match = SUPERDOMAIN_MATCH;
      break;
    }
  }

end:
  k->host = org_ptr;

  if (match_type)
    *match_type = match;

  if (kh)
    memcpy(kh, k, sizeof(struct hsts_kh));
  else
    xfree(k->host);

  xfree(k);
  return khi;
}

static bool
hsts_new_entry_internal(hsts_store_t store, const char* host, int port, int64_t created, int64_t max_age, bool include_subdomains, bool check_validity, bool check_expired, bool check_duplicates) {
  struct hsts_kh* kh = xnew(struct hsts_kh);
  struct hsts_kh_info* khi = xnew0(struct hsts_kh_info);
  bool success = false;

  kh->host = xstrdup_lower(host);
  kh->explicit_port = MAKE_EXPLICIT_PORT(SCHEME_HTTPS, port);

  khi->created = created;
  khi->max_age = max_age;
  khi->include_subdomains = include_subdomains;

  if (check_validity && !hsts_is_host_name_valid(host))
    goto bail;

  if (check_expired && ((khi->created + khi->max_age) < khi->created))
    goto bail;

  if (check_duplicates && hash_table_contains(store->table, kh))
    goto bail;

  hash_table_put(store->table, kh, khi);
  success = true;

bail:
  if (!success) {
    xfree(kh->host);
    xfree(kh);
    xfree(khi);
  }

  return success;
}

/* Creates a new entry without duplicate checks
   Caller must ensure it is not inserting an existing host/port
 */
static bool hsts_add_entry(hsts_store_t store, const char* host, int port, int64_t max_age, bool include_subdomains) {
  int64_t t = (int64_t)time(NULL);

  if (t == -1)
    return false;

  return hsts_new_entry_internal(store, host, port, t, max_age, include_subdomains, false, true, false);
}

/* Creates a new entry, unless an identical one already exists */
static bool hsts_new_entry(hsts_store_t store, const char* host, int port, int64_t created, int64_t max_age, bool include_subdomains) {
  return hsts_new_entry_internal(store, host, port, created, max_age, include_subdomains, true, true, true);
}

static void hsts_remove_entry(hsts_store_t store, struct hsts_kh* kh) {
  hash_table_remove(store->table, kh);
}

static bool hsts_store_merge(hsts_store_t store, const char* host, int port, int64_t created, int64_t max_age, bool include_subdomains) {
  enum hsts_kh_match match_type = NO_MATCH;
  struct hsts_kh_info* khi;
  bool success = false;

  port = MAKE_EXPLICIT_PORT(SCHEME_HTTPS, port);
  khi = hsts_find_entry(store, host, port, &match_type, NULL);
  if (khi && match_type == CONGRUENT_MATCH && created > khi->created) {
    /* update the entry with newer information */
    khi->created = created;
    khi->max_age = max_age;
    khi->include_subdomains = include_subdomains;
    success = true;
  }
  else if (!khi) {
    success = hsts_new_entry(store, host, port, created, max_age, include_subdomains);
  }

  return success;
}

static bool hsts_read_database(hsts_store_t store, FILE* fp, bool merge_with_existing_entries) {
  char* line = NULL;
  char* p;
  size_t len = 0;
  int items_read;
  bool result = false;
  bool (*func)(hsts_store_t, const char*, int, int64_t, int64_t, bool);

  char host[256];
  int port;
  int64_t created;
  int64_t max_age;
  int include_subdomains;

  func = merge_with_existing_entries ? hsts_store_merge : hsts_new_entry;

  while (getline(&line, &len, fp) > 0) {
    for (p = line; c_isspace(*p); p++)
      ;

    if (*p == '#')
      continue;

    items_read = sscanf(p, "%255s %d %d %" SCNd64 " %" SCNd64, host, &port, &include_subdomains, &created, &max_age);

    if (items_read == 5)
      func(store, host, port, created, max_age, !!include_subdomains);
  }

  xfree(line);
  result = true;

  return result;
}

static void hsts_store_dump(hsts_store_t store, FILE* fp) {
  hash_table_iterator it;

  /* header comments are best effort only */
  fputs("# HSTS 1.0 Known Hosts database\n", fp);
  fputs("# Edit at your own risk\n", fp);
  fputs("# <hostname>\t<port>\t<incl. subdomains>\t<created>\t<max-age>\n", fp);

  for (hash_table_iterate(store->table, &it); hash_table_iter_next(&it);) {
    struct hsts_kh* kh = (struct hsts_kh*)it.key;
    struct hsts_kh_info* khi = (struct hsts_kh_info*)it.value;

    if (fprintf(fp, "%s\t%d\t%d\t%" PRId64 "\t%" PRId64 "\n", kh->host, kh->explicit_port, khi->include_subdomains, khi->created, khi->max_age) < 0) {
      logprintf(LOG_ALWAYS, "Could not write the HSTS database correctly\n");
      break;
    }
  }
}

/* Require a regular, non world-writable file */
static bool hsts_file_access_valid(const char* filename) {
  struct stat st;

  if (stat(filename, &st) == -1)
    return false;

  return S_ISREG(st.st_mode) && !(st.st_mode & S_IWOTH);
}

/* HSTS API */

/*
   Apply HSTS policy to the given URL

   If there is a matching host in the store and the entry is still
   valid, rewrite the URL to HTTPS and update port defaults
 */
bool hsts_match(hsts_store_t store, struct url* u) {
  bool url_changed = false;
  struct hsts_kh_info* entry = NULL;
  struct hsts_kh* kh = xnew(struct hsts_kh);
  enum hsts_kh_match match = NO_MATCH;
  int port = MAKE_EXPLICIT_PORT(u->scheme, u->port);

  if (!store) {
    xfree(kh);
    return false;
  }

  hsts_lock(store);

  /* skip work if already HTTPS */
  if (!hsts_is_scheme_valid(u->scheme)) {
    entry = hsts_find_entry(store, u->host, port, &match, kh);
    if (entry) {
      time_t now = time(NULL);

      if (now != (time_t)-1 && (entry->created + entry->max_age) >= now) {
        if (match == CONGRUENT_MATCH || (match == SUPERDOMAIN_MATCH && entry->include_subdomains)) {
          u->scheme = SCHEME_HTTPS;
          if (u->port == DEFAULT_HTTP_PORT)
            u->port = DEFAULT_SSL_PORT;
          url_changed = true;
          store->changed = true;
        }
      }
      else {
        hsts_remove_entry(store, kh);
        store->changed = true;
      }
    }
    xfree(kh->host);
  }

  xfree(kh);
  hsts_unlock(store);

  return url_changed;
}

/*
   Add or update an HSTS Known Host entry

   If max_age is zero and an entry exists, it is removed from the store
   Callers must explicitly flush to disk via hsts_store_save
 */
bool hsts_store_entry(hsts_store_t store, enum url_scheme scheme, const char* host, int port, int64_t max_age, bool include_subdomains) {
  bool result = false;
  enum hsts_kh_match match = NO_MATCH;
  struct hsts_kh* kh = xnew(struct hsts_kh);
  struct hsts_kh_info* entry = NULL;

  if (!store) {
    xfree(kh);
    return false;
  }

  hsts_lock(store);

  if (hsts_is_host_eligible(scheme, host)) {
    port = MAKE_EXPLICIT_PORT(scheme, port);
    entry = hsts_find_entry(store, host, port, &match, kh);

    if (entry && match == CONGRUENT_MATCH) {
      if (max_age == 0) {
        hsts_remove_entry(store, kh);
        store->changed = true;
      }
      else if (max_age > 0) {
        int64_t t = (int64_t)time(NULL);

        if (t != -1 && t != entry->created) {
          entry->created = t;
          entry->max_age = max_age;
          entry->include_subdomains = include_subdomains;
          store->changed = true;
        }
      }
    }
    else if (entry == NULL || match == SUPERDOMAIN_MATCH) {
      /* create a new entry when there is no congruent match */
      result = hsts_add_entry(store, host, port, max_age, include_subdomains);
      if (result)
        store->changed = true;
    }

    xfree(kh->host);
  }

  xfree(kh);
  hsts_unlock(store);

  return result;
}

hsts_store_t hsts_store_open(const char* filename) {
  hsts_store_t store = xnew0(struct hsts_store);
  file_stats_t fstats;

  wget_mutex_init(&store->lock);
  store->table = hash_table_new(0, hsts_hash_func, hsts_cmp_func);
  store->last_mtime = 0;
  store->changed = false;

  if (file_exists_p(filename, &fstats)) {
    if (hsts_file_access_valid(filename)) {
      struct stat st;
      FILE* fp = fopen_stat(filename, "r", &fstats);

      if (!fp || !hsts_read_database(store, fp, false)) {
        hsts_store_close(store);
        xfree(store);
        if (fp)
          fclose(fp);
        return NULL;
      }

      if (fstat(fileno(fp), &st) == 0)
        store->last_mtime = st.st_mtime;

      fclose(fp);
    }
    else {
      hsts_store_close(store);
      xfree(store);

      logprintf(LOG_NOTQUIET,
                "Will not apply HSTS. "
                "The HSTS database must be a regular and non-world-writable file\n");
      return NULL;
    }
  }

  return store;
}

void hsts_store_save(hsts_store_t store, const char* filename) {
  struct stat st;
  FILE* fp;
  int fd;

  if (!store)
    return;

  hsts_lock(store);

  if (filename && hash_table_count(store->table) > 0) {
    fp = fopen(filename, "a+");
    if (fp) {
      fd = fileno(fp);
      flock(fd, LOCK_EX);

      /* merge any external updates from other processes before truncating */
      if (store->last_mtime && stat(filename, &st) == 0 && st.st_mtime > store->last_mtime)
        hsts_read_database(store, fp, true);

      fseek(fp, 0, SEEK_SET);
      if (ftruncate(fd, 0) == -1) {
        /* Ignore truncate errors as we're overwriting the file anyway */
      }

      hsts_store_dump(store, fp);

      fclose(fp);
    }
  }

  hsts_unlock(store);
}

bool hsts_store_has_changed(hsts_store_t store) {
  bool changed = false;

  if (!store)
    return false;

  hsts_lock(store);
  changed = store->changed;
  hsts_unlock(store);

  return changed;
}

void hsts_store_close(hsts_store_t store) {
  hash_table_iterator it;

  if (!store)
    return;

  hsts_lock(store);

  for (hash_table_iterate(store->table, &it); hash_table_iter_next(&it);) {
    xfree(((struct hsts_kh*)it.key)->host);
    xfree(it.key);
    xfree(it.value);
  }

  hash_table_destroy(store->table);
  store->table = NULL;

  hsts_unlock(store);
  wget_mutex_destroy(&store->lock);
}

#ifdef TESTING

/* Test helpers that wrap URL rewrite checks and forward the first failure */

#define TEST_URL_RW(s, u, p)                         \
  do {                                               \
    const char* _msg = test_url_rewrite(s, u, p, 1); \
    if (_msg)                                        \
      return _msg;                                   \
  } while (0)

#define TEST_URL_NORW(s, u, p)                       \
  do {                                               \
    const char* _msg = test_url_rewrite(s, u, p, 0); \
    if (_msg)                                        \
      return _msg;                                   \
  } while (0)

static char* get_hsts_store_filename(void) {
  char* filename = NULL;
  FILE* fp = NULL;

  if (opt.homedir) {
    filename = ajoin_dir_file(opt.homedir, ".wget-hsts-test");
    fp = fopen(filename, "w");
    if (fp)
      fclose(fp);
  }

  return filename;
}

static hsts_store_t open_hsts_test_store(void) {
  char* filename = get_hsts_store_filename();
  hsts_store_t table = hsts_store_open(filename);
  xfree(filename);
  return table;
}

static void close_hsts_test_store(hsts_store_t store) {
  char* filename = get_hsts_store_filename();

  if (filename) {
    unlink(filename);
    xfree(filename);
  }
  xfree(store);
}

static const char* test_url_rewrite(hsts_store_t s, const char* url, int port, bool rewrite) {
  bool result;
  struct url u;

  u.host = xstrdup(url);
  u.port = port;
  u.scheme = SCHEME_HTTP;

  result = hsts_match(s, &u);

  if (rewrite) {
    if (port == 80)
      mu_assert("URL: port should've been rewritten to 443", u.port == 443);
    else
      mu_assert("URL: port should've been left intact", u.port == port);
    mu_assert("URL: scheme should've been rewritten to HTTPS", u.scheme == SCHEME_HTTPS);
    mu_assert("result should've been true", result == true);
  }
  else {
    mu_assert("URL: port should've been left intact", u.port == port);
    mu_assert("URL: scheme should've been left intact", u.scheme == SCHEME_HTTP);
    mu_assert("result should've been false", result == false);
  }

  xfree(u.host);
  return NULL;
}

const char* test_hsts_new_entry(void) {
  enum hsts_kh_match match = NO_MATCH;
  struct hsts_kh_info* khi;
  hsts_store_t s;
  bool created;

  s = open_hsts_test_store();
  mu_assert("Could not open the HSTS store. This could be due to lack of memory.", s != NULL);

  created = hsts_store_entry(s, SCHEME_HTTP, "www.foo.com", 80, 1234, true);
  mu_assert("No entry should have been created.", created == false);

  created = hsts_store_entry(s, SCHEME_HTTPS, "www.foo.com", 443, 1234, true);
  mu_assert("A new entry should have been created", created == true);

  khi = hsts_find_entry(s, "www.foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been a congruent match", match == CONGRUENT_MATCH);
  mu_assert("No valid HSTS info was returned", khi != NULL);
  mu_assert("Variable 'max_age' should be 1234", khi->max_age == 1234);
  mu_assert("Variable 'include_subdomains' should be asserted", khi->include_subdomains == true);

  khi = hsts_find_entry(s, "b.www.foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been a superdomain match", match == SUPERDOMAIN_MATCH);
  mu_assert("No valid HSTS info was returned", khi != NULL);
  mu_assert("Variable 'max_age' should be 1234", khi->max_age == 1234);
  mu_assert("Variable 'include_subdomains' should be asserted", khi->include_subdomains == true);

  khi = hsts_find_entry(s, "ww.foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry(s, "foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry(s, ".foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == NO_MATCH);

  khi = hsts_find_entry(s, ".www.foo.com", MAKE_EXPLICIT_PORT(SCHEME_HTTPS, 443), &match, NULL);
  mu_assert("Should've been no match", match == SUPERDOMAIN_MATCH);

  hsts_store_close(s);
  close_hsts_test_store(s);

  return NULL;
}

const char* test_hsts_url_rewrite_superdomain(void) {
  hsts_store_t s;
  bool created;

  s = open_hsts_test_store();
  mu_assert("Could not open the HSTS store", s != NULL);

  created = hsts_store_entry(s, SCHEME_HTTPS, "example.com", 443, 1234, true);
  mu_assert("A new entry should've been created", created == true);

  created = hsts_store_entry(s, SCHEME_HTTPS, "rep.example.com", 443, 1234, false);
  mu_assert("A new entry should've been created", created == true);

  TEST_URL_RW(s, "example.com", 80);
  TEST_URL_RW(s, "rep.example.com", 80);
  TEST_URL_RW(s, "rep.rep.example.com", 80);

  hsts_store_close(s);
  close_hsts_test_store(s);

  return NULL;
}

const char* test_hsts_url_rewrite_congruent(void) {
  hsts_store_t s;
  bool created;

  s = open_hsts_test_store();
  mu_assert("Could not open the HSTS store", s != NULL);

  created = hsts_store_entry(s, SCHEME_HTTPS, "foo.com", 443, 1234, false);
  mu_assert("A new entry should've been created", created == true);

  TEST_URL_RW(s, "foo.com", 80);
  TEST_URL_NORW(s, "www.foo.com", 80);

  hsts_store_close(s);
  close_hsts_test_store(s);

  return NULL;
}

const char* test_hsts_read_database(void) {
  hsts_store_t table;
  char* file = NULL;
  FILE* fp = NULL;
  int64_t created = time(NULL) - 10;

  if (opt.homedir) {
    file = ajoin_dir_file(opt.homedir, ".wget-hsts-testing");
    fp = fopen(file, "w");
    if (fp) {
      fputs("# dummy comment\n", fp);
      fprintf(fp, "foo.example.com\t0\t1\t%" PRId64 "\t123\n", created);
      fprintf(fp, "bar.example.com\t0\t0\t%" PRId64 "\t456\n", created);
      fprintf(fp, "test.example.com\t8080\t0\t%" PRId64 "\t789\n", created);
      fclose(fp);

      table = hsts_store_open(file);

      TEST_URL_RW(table, "foo.example.com", 80);
      TEST_URL_RW(table, "www.foo.example.com", 80);
      TEST_URL_RW(table, "bar.example.com", 80);

      TEST_URL_NORW(table, "www.bar.example.com", 80);

      TEST_URL_RW(table, "test.example.com", 8080);

      hsts_store_close(table);
      close_hsts_test_store(table);
      unlink(file);
    }
    xfree(file);
  }

  return NULL;
}
#endif /* TESTING */
#endif /* HAVE_HSTS */
