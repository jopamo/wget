/* Various utility functions for wget.
 * src/utils.c
 *
 * This file contains utility functions for:
 * - String manipulation and formatting
 * - File system operations
 * - Memory management
 * - Time and date handling
 * - Base64 encoding/decoding
 * - Regular expression compilation
 * - Random number generation
 * - Process management
 */

#include "wget.h"

#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stdarg.h>
#include <locale.h>
#include <utime.h>

#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <grp.h>

#include <signal.h>
#include <setjmp.h>

#include <regex.h>
#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifndef HAVE_SIGSETJMP
#ifdef sigsetjmp
#define HAVE_SIGSETJMP
#endif
#endif

#if defined HAVE_SIGSETJMP || defined HAVE_SIGBLOCK
#define USE_SIGNAL_TIMEOUT
#endif

#ifdef HAVE_MMAP
#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif
#endif

#include "utils.h"
#include "hash.h"

#ifdef TESTING
#include "../tests/unit-tests.h"
#endif

#include "exits.h"
#include "c-strcase.h"

/*
 * Handle fatal memory allocation errors.
 *
 * @param context: Description of what was being allocated
 * @param attempted_size: Size of memory allocation that failed
 */
_Noreturn static void memfatal(const char* context, long attempted_size) {
  log_set_save_context(false);

  if (attempted_size == UNKNOWN_ATTEMPTED_SIZE) {
    logprintf(LOG_ALWAYS, _("%s: %s: Failed to allocate enough memory; memory exhausted\n"), exec_name, context);
  }
  else {
    logprintf(LOG_ALWAYS, _("%s: %s: Failed to allocate %ld bytes; memory exhausted\n"), exec_name, context, attempted_size);
  }

  exit(WGET_EXIT_GENERIC_ERROR);
}

/* Character property table for URL encoding/decoding
 * Bit flags:
 * - 0x01: Reserved characters (must be encoded)
 * - 0x02: Space character
 * - 0x04: Path separator
 * - 0x08: Control characters
 * - 0x10: Unreserved characters (don't encode)
 * - 0x20: Lowercase letters
 * - 0x40: Uppercase letters
 * - 0x80: Digits
 */
unsigned char char_prop[256] = {0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  2,  1,  1,  1,  16,
                                1,  1,  1,  1,  1,  0,  1,  1,  16, 4,  0,  80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 1,  1, 1,  1,  1,  1,  1,  80, 80, 80, 80, 80, 80, 16, 16, 16,
                                16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 1,  1,  1,  1,  16, 1, 96, 96, 96, 96, 96, 96, 32, 32, 32, 32, 32, 32, 32, 32,
                                32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 1,  1,  1,  17, 8,  8,  8,  8,  8,  8,  8, 8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
                                8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
                                0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  8};

/*
 * Duplicate a string and convert it to lowercase.
 *
 * @param s: String to duplicate and convert
 * @return: New lowercase string (must be freed by caller)
 */
char* xstrdup_lower(const char* s) {
  char* copy = xstrdup(s);
  char* p = copy;
  for (; *p; p++)
    *p = c_tolower(*p);
  return copy;
}

/*
 * Duplicate a substring between two pointers.
 *
 * @param beg: Start of substring
 * @param end: End of substring (exclusive)
 * @return: New string containing substring (must be freed by caller)
 */
char* strdupdelim(const char* beg, const char* end) {
  if (beg && beg <= end) {
    size_t len = (size_t)(end - beg);
    char* res = xmalloc(len + 1);
    memcpy(res, beg, len);
    res[len] = '\0';
    return res;
  }

  return xstrdup("");
}

/*
 * Split a comma-separated string into an array of strings.
 * Handles optional whitespace around commas.
 *
 * @param s: Comma-separated string to split
 * @return: NULL-terminated array of strings (must be freed with free_vec)
 */
char** sepstring(const char* s) {
  char** res;
  const char* p;
  int i = 0;

  if (!s || !*s)
    return NULL;

  res = NULL;
  p = s;
  while (*s) {
    if (*s == ',') {
      res = xrealloc(res, (i + 2) * sizeof(char*));
      res[i] = strdupdelim(p, s);
      res[++i] = NULL;
      ++s;

      while (c_isspace(*s))
        ++s;
      p = s;
    }
    else
      ++s;
  }
  res = xrealloc(res, (i + 2) * sizeof(char*));
  res[i] = strdupdelim(p, s);
  res[i + 1] = NULL;
  return res;
}

/*
 * Allocate and format a string (printf-like with automatic memory allocation).
 * Uses vasprintf() if available, otherwise implements a fallback.
 *
 * @param fmt: Format string (printf-style)
 * @param ...: Arguments for format string
 * @return: Formatted string (must be freed by caller), or NULL on error
 */
char* aprintf(const char* fmt, ...) {
#if defined HAVE_VASPRINTF && !defined DEBUG_MALLOC
  int ret;
  va_list args;
  char* str;
  va_start(args, fmt);
  ret = vasprintf(&str, fmt, args);
  va_end(args);
  if (ret < 0 && errno == ENOMEM)
    memfatal("aprintf", UNKNOWN_ATTEMPTED_SIZE);
  else if (ret < 0)
    return NULL;
  return str;
#else
#define FMT_MAX_LENGTH 1048576

  int size = 32;
  char* str = xmalloc((size_t)size);

  while (1) {
    int n;
    va_list args;

    va_start(args, fmt);
    n = vsnprintf(str, (size_t)size, fmt, args);
    va_end(args);

    if (n > -1 && n < size)
      return str;

    if (n > -1)
      size = n + 1;
    else if (size >= FMT_MAX_LENGTH) {
      logprintf(LOG_ALWAYS, _("%s: aprintf: text buffer is too big (%d bytes), aborting\n"), exec_name, size);
      abort();
    }
    else {
      size <<= 1;
    }
    str = xrealloc(str, (size_t)size);
  }
#endif
}

#include <stdarg.h>
#include <string.h>

size_t wget_strlcpy(char* dst, const char* src, size_t size) {
  const char* old = src;

  if (size) {
    while (--size) {
      if (!(*dst++ = *src++))
        return (size_t)(src - old - 1);
    }
    *dst = 0;
  }

  while (*src++)
    ;
  return (size_t)(src - old - 1);
}

char* concat_strings(const char* str0, ...) {
  va_list args;
  const char* arg;
  size_t length = 0;
  size_t pos = 0;
  char* s;

  if (!str0)
    return NULL;

  va_start(args, str0);
  for (arg = str0; arg; arg = va_arg(args, const char*))
    length += strlen(arg);
  va_end(args);

  s = xmalloc(length + 1);

  va_start(args, str0);
  for (arg = str0; arg; arg = va_arg(args, const char*)) {
    size_t copied = wget_strlcpy(s + pos, arg, length - pos + 1);
    pos += copied;
  }
  va_end(args);

  return s;
}

static char* fmttime(time_t t, const char* fmt) {
  static char output[32];
  struct tm* tm = localtime(&t);
  if (!tm)
    abort();
  if (!strftime(output, sizeof(output), fmt, tm))
    abort();
  return output;
}

char* time_str(time_t t) {
  return fmttime(t, "%H:%M:%S");
}

char* datetime_str(time_t t) {
  return fmttime(t, "%Y-%m-%d %H:%M:%S");
}

/*
 * Fork the current process to run in the background (daemonize).
 * Redirects stdio to /dev/null and creates a new session.
 *
 * @return: true if log file was changed, false otherwise
 */
bool fork_to_background(void) {
  pid_t pid;
  bool logfile_changed = false;

  if (!opt.lfilename && (!opt.quiet || opt.server_response)) {
    FILE* new_log_fp = unique_create(DEFAULT_LOGFILE, false, &opt.lfilename);
    if (new_log_fp) {
      logfile_changed = true;
      fclose(new_log_fp);
    }
  }

  pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(WGET_EXIT_GENERIC_ERROR);
  }
  else if (pid != 0) {
    printf(_("Continuing in background, pid %d\n"), (int)pid);
    if (logfile_changed)
      printf(_("Output will be written to %s\n"), quote(opt.lfilename));
    exit(WGET_EXIT_SUCCESS);
  }

  setsid();
  if (freopen("/dev/null", "r", stdin) == NULL)
    DEBUGP(("Failed to redirect stdin to /dev/null\n"));
  if (freopen("/dev/null", "w", stdout) == NULL)
    DEBUGP(("Failed to redirect stdout to /dev/null\n"));
  if (freopen("/dev/null", "w", stderr) == NULL)
    DEBUGP(("Failed to redirect stderr to /dev/null\n"));

  return logfile_changed;
}

/*
 * Update file modification time (like Unix 'touch' command).
 *
 * @param file: Path to file
 * @param tm: New modification time (access time set to current time)
 */
void touch(const char* file, time_t tm) {
  struct utimbuf times;

  times.modtime = tm;
  times.actime = time(NULL);

  if (utime(file, &times) == -1)
    logprintf(LOG_NOTQUIET, "utime(%s): %s\n", file, strerror(errno));
}

int remove_link(const char* file) {
  int err = 0;
  struct stat st;

  if (lstat(file, &st) == 0 && S_ISLNK(st.st_mode)) {
    DEBUGP(("Unlinking %s (symlink)\n", file));
    err = unlink(file);
    if (err != 0)
      logprintf(LOG_VERBOSE, _("Failed to unlink symlink %s: %s\n"), quote(file), strerror(errno));
  }
  return err;
}

static bool is_group_member(gid_t gid) {
  int ngroups = getgroups(0, NULL);
  gid_t* groups = NULL;
  bool result = false;

  if (ngroups < 0)
    return false;

  groups = malloc((size_t)ngroups * sizeof(gid_t));
  if (!groups)
    return false;

  if (getgroups(ngroups, groups) >= 0) {
    for (int i = 0; i < ngroups; i++) {
      if (groups[i] == gid) {
        result = true;
        break;
      }
    }
  }

  free(groups);
  return result;
}

/*
 * Check if a file exists and is readable.
 * Also checks file permissions and group membership.
 *
 * @param filename: Path to file to check
 * @param fstats: Optional pointer to store file statistics
 * @return: true if file exists and is readable, false otherwise
 */
bool file_exists_p(const char* filename, file_stats_t* fstats) {
  struct stat buf;

  if (!filename)
    return false;

  errno = 0;
  if (stat(filename, &buf) == 0 && S_ISREG(buf.st_mode) &&
      (((S_IRUSR & buf.st_mode) && (getuid() == buf.st_uid)) || ((S_IRGRP & buf.st_mode) && is_group_member(buf.st_gid)) || (S_IROTH & buf.st_mode))) {
    if (fstats != NULL) {
      fstats->access_err = 0;
      fstats->st_ino = buf.st_ino;
      fstats->st_dev = buf.st_dev;
    }
    return true;
  }
  else {
    if (fstats != NULL)
      fstats->access_err = (errno == 0 ? EACCES : errno);
    errno = 0;
    return false;
  }
}

bool file_non_directory_p(const char* path) {
  struct stat buf;

  if (lstat(path, &buf) != 0)
    return false;
  return !S_ISDIR(buf.st_mode);
}

wgint file_size(const char* filename) {
#if defined(HAVE_FSEEKO) && defined(HAVE_FTELLO)
  wgint size;
  FILE* fp = fopen(filename, "rb");
  if (!fp)
    return -1;
  fseeko(fp, 0, SEEK_END);
  size = ftello(fp);
  fclose(fp);
  return size;
#else
  struct stat st;
  if (stat(filename, &st) < 0)
    return -1;
  return st.st_size;
#endif
}

#ifdef UNIQ_SEP

static char* unique_name_1(const char* prefix) {
  int count = 1;
  size_t plen = strlen(prefix);
  char* template = xmalloc(plen + 1 + 24);
  char* template_tail = template + plen;

  memcpy(template, prefix, plen);
  *template_tail++ = UNIQ_SEP;

  do
    number_to_string(template_tail, count++);
  while (file_exists_p(template, NULL) && count < 999999);

  return template;
}

char* unique_name_passthrough(const char* file) {
  return file_exists_p(file, NULL) ? unique_name_1(file) : (char*)file;
}

char* unique_name(const char* file) {
  return file_exists_p(file, NULL) ? unique_name_1(file) : xstrdup(file);
}

#else

char* unique_name_passthrough(const char* file, bool allow_passthrough) {
  (void)allow_passthrough;
  return (char*)file;
}

char* unique_name(const char* file) {
  return xstrdup(file);
}

#endif

FILE* unique_create(const char* name, bool binary, char** opened_name) {
  char* uname = unique_name(name);
  FILE* fp;

  while ((fp = fopen_excl(uname, binary)) == NULL && errno == EEXIST) {
    xfree(uname);
    uname = unique_name(name);
  }

  if (opened_name) {
    if (fp)
      *opened_name = uname;
    else {
      *opened_name = NULL;
      xfree(uname);
    }
  }
  else
    xfree(uname);

  return fp;
}

FILE* fopen_excl(const char* fname, int binary) {
  int fd;
#ifdef O_EXCL
  int flags = O_WRONLY | O_CREAT | O_EXCL;

  fd = open(fname, flags, 0666);
  if (fd < 0)
    return NULL;
  return fdopen(fd, binary ? "wb" : "w");
#else
  if (file_exists_p(fname, NULL)) {
    errno = EEXIST;
    return NULL;
  }
  return fopen(fname, binary ? "wb" : "w");
#endif
}

FILE* fopen_stat(const char* fname, const char* mode, file_stats_t* fstats) {
  int fd;
  FILE* fp;
  struct stat fdstats;

#if defined FUZZING && defined TESTING
  fp = fopen_wgetrc(fname, mode);
#else
  fp = fopen(fname, mode);
#endif
  if (fp == NULL) {
    logprintf(LOG_NOTQUIET, _("Failed to Fopen file %s\n"), fname);
    return NULL;
  }

  fd = fileno(fp);
  if (fd < 0) {
    logprintf(LOG_NOTQUIET, _("Failed to get FD for file %s\n"), fname);
    fclose(fp);
    return NULL;
  }

  memset(&fdstats, 0, sizeof(fdstats));
  if (fstat(fd, &fdstats) == -1) {
    logprintf(LOG_NOTQUIET, _("Failed to stat file %s, (check permissions)\n"), fname);
    fclose(fp);
    return NULL;
  }

  if (fstats != NULL && (fdstats.st_dev != fstats->st_dev || fdstats.st_ino != fstats->st_ino)) {
    logprintf(LOG_NOTQUIET, _("File %s changed since the last check. Security check failed\n"), fname);
    fclose(fp);
    return NULL;
  }

  return fp;
}

int open_stat(const char* fname, int flags, mode_t mode, file_stats_t* fstats) {
  int fd;
  struct stat fdstats;

  fd = open(fname, flags, mode);
  if (fd < 0) {
    logprintf(LOG_NOTQUIET, _("Failed to open file %s, reason :%s\n"), fname, strerror(errno));
    return -1;
  }

  memset(&fdstats, 0, sizeof(fdstats));
  if (fstat(fd, &fdstats) == -1) {
    logprintf(LOG_NOTQUIET, _("Failed to stat file %s, error: %s\n"), fname, strerror(errno));
    close(fd);
    return -1;
  }

  if (fstats != NULL && (fdstats.st_dev != fstats->st_dev || fdstats.st_ino != fstats->st_ino)) {
    logprintf(LOG_NOTQUIET, _("Trying to open file %s but it changed since last check. Security check failed\n"), fname);
    close(fd);
    return -1;
  }

  return fd;
}

int make_directory(const char* directory) {
  int i, ret = 0, quit = 0;
  char buf[1024];
  char* dir;
  size_t len = strlen(directory);

  if (len < sizeof(buf)) {
    memcpy(buf, directory, len + 1);
    dir = buf;
  }
  else
    dir = xstrdup(directory);

  for (i = (*dir == '/'); 1; ++i) {
    for (; dir[i] && dir[i] != '/'; i++)
      ;
    if (!dir[i])
      quit = 1;
    dir[i] = '\0';

    if (!file_exists_p(dir, NULL))
      ret = mkdir(dir, 0777);
    else
      ret = 0;

    if (quit)
      break;
    else
      dir[i] = '/';
  }

  if (dir != buf)
    xfree(dir);

  return ret;
}

char* file_merge(const char* base, const char* file) {
  char* result;
  const char* cut = strrchr(base, '/');

  if (!cut)
    return xstrdup(file);

  result = xmalloc((size_t)(cut - base) + 1 + strlen(file) + 1);
  memcpy(result, base, (size_t)(cut - base));
  result[cut - base] = '/';
  strcpy(result + (cut - base) + 1, file);

  return result;
}

int fnmatch_nocase(const char* pattern, const char* string, int flags) {
  return fnmatch(pattern, string, flags | FNM_CASEFOLD);
}

static bool in_acclist(const char* const*, const char*, bool);

bool acceptable(const char* s) {
  const char* p;

  if (opt.output_document && strcmp(s, opt.output_document) == 0)
    return true;

  if ((p = strrchr(s, '/')))
    s = p + 1;

  if (opt.accepts) {
    if (opt.rejects)
      return (in_acclist((const char* const*)opt.accepts, s, true) && !in_acclist((const char* const*)opt.rejects, s, true));
    else
      return in_acclist((const char* const*)opt.accepts, s, true);
  }
  else if (opt.rejects)
    return !in_acclist((const char* const*)opt.rejects, s, true);

  return true;
}

bool accept_url(const char* s) {
  if (opt.acceptregex && !opt.regex_match_fun(opt.acceptregex, s))
    return false;
  if (opt.rejectregex && opt.regex_match_fun(opt.rejectregex, s))
    return false;

  return true;
}

bool subdir_p(const char* d1, const char* d2) {
  if (*d1 == '\0')
    return true;

  if (!opt.ignore_case) {
    for (; *d1 && *d2 && (*d1 == *d2); ++d1, ++d2)
      ;
  }
  else {
    for (; *d1 && *d2 && (c_tolower(*d1) == c_tolower(*d2)); ++d1, ++d2)
      ;
  }

  return *d1 == '\0' && (*d2 == '\0' || *d2 == '/');
}

static bool dir_matches_p(const char** dirlist, const char* dir) {
  const char** x;
  int (*matcher)(const char*, const char*, int) = opt.ignore_case ? fnmatch_nocase : fnmatch;

  for (x = dirlist; *x; x++) {
    const char* p = *x + (**x == '/');
    if (has_wildcards_p(p)) {
      if (matcher(p, dir, FNM_PATHNAME) == 0)
        break;
    }
    else {
      if (subdir_p(p, dir))
        break;
    }
  }

  return *x != NULL;
}

bool accdir(const char* directory) {
  if (*directory == '/')
    ++directory;
  if (opt.includes) {
    if (!dir_matches_p(opt.includes, directory))
      return false;
  }
  if (opt.excludes) {
    if (dir_matches_p(opt.excludes, directory))
      return false;
  }
  return true;
}

bool match_tail(const char* string, const char* tail, bool fold_case) {
  int pos = (int)strlen(string) - (int)strlen(tail);

  if (pos < 0)
    return false;

  if (!fold_case)
    return !strcmp(string + pos, tail);
  else
    return !strcasecmp(string + pos, tail);
}

static bool in_acclist(const char* const* accepts, const char* s, bool backward) {
  for (; *accepts; accepts++) {
    if (has_wildcards_p(*accepts)) {
      int res = opt.ignore_case ? fnmatch_nocase(*accepts, s, 0) : fnmatch(*accepts, s, 0);

      if (res == 0)
        return true;
    }
    else {
      if (backward) {
        if (match_tail(s, *accepts, opt.ignore_case))
          return true;
      }
      else {
        int cmp = opt.ignore_case ? strcasecmp(s, *accepts) : strcmp(s, *accepts);
        if (cmp == 0)
          return true;
      }
    }
  }
  return false;
}

char* suffix(const char* str) {
  char* p;

  if ((p = strrchr(str, '.')) && !strchr(p + 1, '/'))
    return p + 1;

  return NULL;
}

bool has_wildcards_p(const char* s) {
  return !!strpbrk(s, "*?[]");
}

bool has_html_suffix_p(const char* fname) {
  char* suf;

  if ((suf = suffix(fname)) == NULL)
    return false;
  if (!c_strcasecmp(suf, "html"))
    return true;
  if (!c_strcasecmp(suf, "htm"))
    return true;
  if (suf[0] && !c_strcasecmp(suf + 1, "html"))
    return true;
  return false;
}

struct file_memory* wget_read_file(const char* file) {
  bool left_open;
  return wget_read_from_file(file, &left_open);
}

static void set_fd_nonblocking(const int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

struct file_memory* wget_read_from_file(const char* file, bool* left_open) {
  int fd;
  struct file_memory* fm;
  long size;
  bool inhibit_close = false;

  if (left_open)
    *left_open = false;

#ifndef FUZZING
  if (HYPHENP(file)) {
    fd = fileno(stdin);
    inhibit_close = true;
  }
  else
#endif
    fd = open(file, O_RDONLY);

  if (fd < 0)
    return NULL;

  set_fd_nonblocking(fd);

  fm = xnew(struct file_memory);

#ifdef HAVE_MMAP
  {
    struct stat buf;
    if (fstat(fd, &buf) < 0)
      goto mmap_lose;
    fm->length = buf.st_size;

    fm->content = mmap(NULL, fm->length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (fm->content == (char*)MAP_FAILED)
      goto mmap_lose;
    if (!inhibit_close)
      close(fd);

    fm->mmap_p = 1;
    return fm;
  }

mmap_lose:
#endif

  fm->length = 0;
  size = 512;
  fm->content = xmalloc((size_t)size);

  while (1) {
    wgint nread;

    if (fm->length > size / 2) {
      size <<= 1;
      fm->content = xrealloc(fm->content, (size_t)size);
    }

    nread = read(fd, fm->content + fm->length, (size_t)(size - fm->length));
    if (nread > 0) {
      fm->length += nread;
    }
    else if (nread < 0) {
      if (errno == EAGAIN) {
        if (left_open)
          *left_open = true;
        break;
      }
      else {
        goto lose;
      }
    }
    else {
      if (left_open)
        *left_open = false;
      break;
    }
  }

  if (!inhibit_close)
    close(fd);

  if (size > fm->length && fm->length != 0)
    fm->content = xrealloc(fm->content, fm->length);

  fm->mmap_p = 0;
  return fm;

lose:
  if (!inhibit_close)
    close(fd);
  xfree(fm->content);
  xfree(fm);
  return NULL;
}

void wget_read_file_free(struct file_memory* fm) {
#ifdef HAVE_MMAP
  if (fm->mmap_p) {
    munmap(fm->content, fm->length);
  }
  else
#endif
  {
    xfree(fm->content);
  }
  xfree(fm);
}

/*
 * Free a NULL-terminated array of strings.
 *
 * @param vec: Array of strings to free (can be NULL)
 */
void free_vec(char** vec) {
  if (vec) {
    char** p = vec;
    while (*p) {
      xfree(*p);
      p++;
    }
    xfree(vec);
  }
}

char** merge_vecs(char** v1, char** v2) {
  int i, j;

  if (!v1)
    return v2;
  if (!v2)
    return v1;
  if (!*v2) {
    xfree(v2);
    return v1;
  }

  for (i = 0; v1[i]; i++)
    ;
  for (j = 0; v2[j]; j++)
    ;

  v1 = xrealloc(v1, (size_t)(i + j + 1) * sizeof(char*));
  memcpy(v1 + i, v2, (size_t)(j + 1) * sizeof(char*));
  xfree(v2);
  return v1;
}

char** vec_append(char** vec, const char* str) {
  int cnt;

  if (vec != NULL) {
    for (cnt = 0; vec[cnt]; cnt++)
      ;
    ++cnt;
  }
  else
    cnt = 1;

  vec = xrealloc(vec, (size_t)(cnt + 1) * sizeof(char*));
  vec[cnt - 1] = xstrdup(str);
  vec[cnt] = NULL;
  return vec;
}

void string_set_add(struct hash_table* ht, const char* s) {
  if (hash_table_contains(ht, s))
    return;

  hash_table_put(ht, xstrdup(s), "1");
}

int string_set_contains(struct hash_table* ht, const char* s) {
  return hash_table_contains(ht, s);
}

void string_set_to_array(struct hash_table* ht, char** array) {
  hash_table_iterator iter;
  for (hash_table_iterate(ht, &iter); hash_table_iter_next(&iter);)
    *array++ = iter.key;
}

void string_set_free(struct hash_table* ht) {
  hash_table_iterator iter;
  for (hash_table_iterate(ht, &iter); hash_table_iter_next(&iter);)
    xfree(iter.key);
  hash_table_destroy(ht);
}

void free_keys_and_values(struct hash_table* ht) {
  hash_table_iterator iter;
  for (hash_table_iterate(ht, &iter); hash_table_iter_next(&iter);) {
    xfree(iter.key);
    xfree(iter.value);
  }
}

static void get_grouping_data(const char** sep, const char** grouping) {
  static const char* cached_sep;
  static const char* cached_grouping;
  static bool initialized;

  if (!initialized) {
    struct lconv* lconv = localeconv();
    cached_sep = lconv->thousands_sep;
    cached_grouping = lconv->grouping;
#if !USE_NLS_PROGRESS_BAR
    if (strlen(cached_sep) > 1)
      cached_sep = "";
#endif
    if (!*cached_sep) {
      if (*lconv->decimal_point != ',')
        cached_sep = ",";
      else
        cached_sep = ".";
      cached_grouping = "\x03";
    }
    initialized = true;
  }
  *sep = cached_sep;
  *grouping = cached_grouping;
}

/*
 * Format a number with thousand separators according to locale.
 *
 * @param n: Number to format
 * @return: Pointer to static buffer containing formatted string
 */
const char* with_thousand_seps(wgint n) {
  static char outbuf[48];
  char* p = outbuf + sizeof outbuf;

  const char *grouping, *sep;
  int seplen;

  int i = 0, groupsize;
  const char* atgroup;

  bool negative = n < 0;

  get_grouping_data(&sep, &grouping);
  seplen = (int)strlen(sep);
  atgroup = grouping;
  groupsize = *atgroup++;

  if (negative)
    n = -n;

  *--p = '\0';
  while (1) {
    *--p = (char)(n % 10 + '0');
    n /= 10;
    if (n == 0)
      break;

    if (++i == groupsize) {
      if (seplen == 1)
        *--p = *sep;
      else
        memcpy(p -= seplen, sep, (size_t)seplen);
      i = 0;
      if (*atgroup)
        groupsize = *atgroup++;
    }
  }
  if (negative)
    *--p = '-';

  return p;
}

/*
 * Convert a number to human-readable format with appropriate unit suffix.
 * Uses binary prefixes (K=1024, M=1024^2, etc.).
 *
 * @param n: Number to format
 * @param acc: Accuracy threshold - show decimals if value < acc
 * @param decimals: Number of decimal places to show
 * @return: Pointer to static buffer containing formatted string
 */
char* human_readable(wgint n, const int acc, const int decimals) {
  static char powers[] = {'K', 'M', 'G', 'T', 'P', 'E'};
  static char buf[8];
  size_t i;

  if (n < 1024) {
    snprintf(buf, sizeof(buf), "%d", (int)n);
    return buf;
  }

  for (i = 0; i < countof(powers); i++) {
    if ((n / 1024) < 1024 || i == countof(powers) - 1) {
      double val = n / 1024.0;
      snprintf(buf, sizeof(buf), "%.*f%c", val < acc ? decimals : 0, val, powers[i]);
      return buf;
    }
    n /= 1024;
  }
  return NULL;
}

int numdigit(wgint number) {
  int cnt = 1;
  if (number < 0)
    ++cnt;
  while ((number /= 10) != 0)
    ++cnt;
  return cnt;
}

#define PR(mask) *p++ = (char)(n / (mask) + '0')

#define DIGITS_1(mask) PR(mask)
#define DIGITS_2(mask) PR(mask), n %= (mask), DIGITS_1((mask) / 10)
#define DIGITS_3(mask) PR(mask), n %= (mask), DIGITS_2((mask) / 10)
#define DIGITS_4(mask) PR(mask), n %= (mask), DIGITS_3((mask) / 10)
#define DIGITS_5(mask) PR(mask), n %= (mask), DIGITS_4((mask) / 10)
#define DIGITS_6(mask) PR(mask), n %= (mask), DIGITS_5((mask) / 10)
#define DIGITS_7(mask) PR(mask), n %= (mask), DIGITS_6((mask) / 10)
#define DIGITS_8(mask) PR(mask), n %= (mask), DIGITS_7((mask) / 10)
#define DIGITS_9(mask) PR(mask), n %= (mask), DIGITS_8((mask) / 10)
#define DIGITS_10(mask) PR(mask), n %= (mask), DIGITS_9((mask) / 10)
#define DIGITS_11(mask) PR(mask), n %= (mask), DIGITS_10((mask) / 10)
#define DIGITS_12(mask) PR(mask), n %= (mask), DIGITS_11((mask) / 10)
#define DIGITS_13(mask) PR(mask), n %= (mask), DIGITS_12((mask) / 10)
#define DIGITS_14(mask) PR(mask), n %= (mask), DIGITS_13((mask) / 10)
#define DIGITS_15(mask) PR(mask), n %= (mask), DIGITS_14((mask) / 10)
#define DIGITS_16(mask) PR(mask), n %= (mask), DIGITS_15((mask) / 10)
#define DIGITS_17(mask) PR(mask), n %= (mask), DIGITS_16((mask) / 10)
#define DIGITS_18(mask) PR(mask), n %= (mask), DIGITS_17((mask) / 10)
#define DIGITS_19(mask) PR(mask), n %= (mask), DIGITS_18((mask) / 10)

#define W wgint

char* number_to_string(char* buffer, wgint number) {
  char* p = buffer;
  wgint n = number;
  int last_digit_char = 0;

  if (n < 0) {
    if (n < -WGINT_MAX) {
      int last_digit = (int)(n % 10);

      if (last_digit < 0)
        last_digit_char = '0' - last_digit;
      else
        last_digit_char = '0' + last_digit;

      n /= 10;
    }

    *p++ = '-';
    n = -n;
  }

  if (n < 10)
    DIGITS_1(1);
  else if (n < 100)
    DIGITS_2(10);
  else if (n < 1000)
    DIGITS_3(100);
  else if (n < 10000)
    DIGITS_4(1000);
  else if (n < 100000)
    DIGITS_5(10000);
  else if (n < 1000000)
    DIGITS_6(100000);
  else if (n < 10000000)
    DIGITS_7(1000000);
  else if (n < 100000000)
    DIGITS_8(10000000);
  else if (n < 1000000000)
    DIGITS_9(100000000);
  else if (n < 10 * (W)1000000000)
    DIGITS_10(1000000000);
  else if (n < 100 * (W)1000000000)
    DIGITS_11(10 * (W)1000000000);
  else if (n < 1000 * (W)1000000000)
    DIGITS_12(100 * (W)1000000000);
  else if (n < 10000 * (W)1000000000)
    DIGITS_13(1000 * (W)1000000000);
  else if (n < 100000 * (W)1000000000)
    DIGITS_14(10000 * (W)1000000000);
  else if (n < 1000000 * (W)1000000000)
    DIGITS_15(100000 * (W)1000000000);
  else if (n < 10000000 * (W)1000000000)
    DIGITS_16(1000000 * (W)1000000000);
  else if (n < 100000000 * (W)1000000000)
    DIGITS_17(10000000 * (W)1000000000);
  else if (n < 1000000000 * (W)1000000000)
    DIGITS_18(100000000 * (W)1000000000);
  else
    DIGITS_19(1000000000 * (W)1000000000);

  if (last_digit_char)
    *p++ = (char)last_digit_char;

  *p = '\0';
  return p;
}

#undef PR
#undef W
#undef DIGITS_1
#undef DIGITS_2
#undef DIGITS_3
#undef DIGITS_4
#undef DIGITS_5
#undef DIGITS_6
#undef DIGITS_7
#undef DIGITS_8
#undef DIGITS_9
#undef DIGITS_10
#undef DIGITS_11
#undef DIGITS_12
#undef DIGITS_13
#undef DIGITS_14
#undef DIGITS_15
#undef DIGITS_16
#undef DIGITS_17
#undef DIGITS_18
#undef DIGITS_19

#define RING_SIZE 3

char* number_to_static_string(wgint number) {
  static char ring[RING_SIZE][24];
  static int ringpos;
  char* buf = ring[ringpos];

  number_to_string(buf, number);
  ringpos = (ringpos + 1) % RING_SIZE;
  return buf;
}

wgint convert_to_bits(wgint num) {
  if (opt.report_bps)
    return num * 8;
  return num;
}

int determine_screen_width(void) {
#ifdef TIOCGWINSZ
  int fd;
  struct winsize wsz;

  if (opt.lfilename != NULL && opt.show_progress != 1)
    return 0;

  fd = fileno(stderr);
  if (ioctl(fd, TIOCGWINSZ, &wsz) < 0)
    return 0;

  return wsz.ws_col;
#else
  return 0;
#endif
}

static int rnd_seeded;

int random_number(int max) {
#ifdef HAVE_RANDOM
  if (!rnd_seeded) {
    srandom((long)time(NULL) ^ (long)getpid());
    rnd_seeded = 1;
  }
  return (int)(random() % max);
#elif defined HAVE_DRAND48
  if (!rnd_seeded) {
    srand48((long)time(NULL) ^ (long)getpid());
    rnd_seeded = 1;
  }
  return (int)(lrand48() % max);
#else
  double bounded;
  int rnd;

  if (!rnd_seeded) {
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    rnd_seeded = 1;
  }
  rnd = rand();

  bounded = (double)max * rnd / (RAND_MAX + 1.0);
  return (int)bounded;
#endif
}

double random_float(void) {
#ifdef HAVE_RANDOM
  return ((double)random_number(RAND_MAX)) / RAND_MAX;
#elif defined HAVE_DRAND48
  if (!rnd_seeded) {
    srand48((long)time(NULL) ^ (long)getpid());
    rnd_seeded = 1;
  }
  return drand48();
#else
  return (random_number(10000) / 10000.0 + random_number(10000) / (10000.0 * 10000.0) + random_number(10000) / (10000.0 * 10000.0 * 10000.0) +
          random_number(10000) / (10000.0 * 10000.0 * 10000.0 * 10000.0));
#endif
}

#ifdef USE_SIGNAL_TIMEOUT

#ifdef HAVE_SIGSETJMP
#define SETJMP(env) sigsetjmp(env, 1)

static sigjmp_buf run_with_timeout_env;

_Noreturn static void abort_run_with_timeout(int sig WGET_ATTR_UNUSED) {
  assert(sig == SIGALRM);
  siglongjmp(run_with_timeout_env, -1);
}
#else
#define SETJMP(env) setjmp(env)

static jmp_buf run_with_timeout_env;

_Noreturn static void abort_run_with_timeout(int sig WGET_ATTR_UNUSED) {
  assert(sig == SIGALRM);

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  sigprocmask(SIG_BLOCK, &set, NULL);

  longjmp(run_with_timeout_env, -1);
}
#endif

static void alarm_set(double timeout) {
#ifdef ITIMER_REAL
  struct itimerval itv;
  xzero(itv);
  itv.it_value.tv_sec = (long)timeout;
  itv.it_value.tv_usec = (suseconds_t)(1000000 * (timeout - (long)timeout));
  if (itv.it_value.tv_sec == 0 && itv.it_value.tv_usec == 0)
    itv.it_value.tv_usec = 1;
  setitimer(ITIMER_REAL, &itv, NULL);
#else
  int secs = (int)timeout;
  if (secs == 0)
    secs = 1;
  alarm(secs);
#endif
}

static void alarm_cancel(void) {
#ifdef ITIMER_REAL
  struct itimerval disable;
  xzero(disable);
  setitimer(ITIMER_REAL, &disable, NULL);
#else
  alarm(0);
#endif
}

bool run_with_timeout(double timeout, void (*fun)(void*), void* arg) {
  int saved_errno;

  if (timeout == 0) {
    fun(arg);
    return false;
  }

  signal(SIGALRM, abort_run_with_timeout);

  if (SETJMP(run_with_timeout_env) != 0) {
    signal(SIGALRM, SIG_DFL);
    return true;
  }

  alarm_set(timeout);
  fun(arg);

  saved_errno = errno;
  alarm_cancel();
  signal(SIGALRM, SIG_DFL);
  errno = saved_errno;

  return false;
}

#else

bool run_with_timeout(double timeout, void (*fun)(void*), void* arg) {
  (void)timeout;
  fun(arg);
  return false;
}

#endif

#if defined FUZZING && defined TESTING
void xsleep(double seconds) {
  (void)seconds;
}
#else
void xsleep(double seconds) {
#ifdef HAVE_NANOSLEEP
  struct timespec sleep_ts, remaining;
  sleep_ts.tv_sec = (time_t)seconds;
  sleep_ts.tv_nsec = (long)(1000000000 * (seconds - (long)seconds));
  while (nanosleep(&sleep_ts, &remaining) < 0 && errno == EINTR)
    sleep_ts = remaining;
#elif defined(HAVE_USLEEP)
  if (seconds >= 1) {
    sleep((unsigned long)seconds);
    seconds -= (long)seconds;
  }
  usleep((useconds_t)(seconds * 1000000));
#else
  struct timeval sleep_tv;
  sleep_tv.tv_sec = (time_t)seconds;
  sleep_tv.tv_usec = (suseconds_t)(1000000 * (seconds - (long)seconds));
  select(0, NULL, NULL, NULL, &sleep_tv);
#endif
}
#endif

/*
 * Base64 encode binary data.
 *
 * @param data: Binary data to encode
 * @param length: Length of data in bytes
 * @param dest: Output buffer (must be large enough for encoded data)
 * @return: Length of encoded string (excluding null terminator)
 */
size_t wget_base64_encode(const void* data, size_t length, char* dest) {
  static const char tbl[64] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                               'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

  const unsigned char* s = data;
  const unsigned char* end = (const unsigned char*)data + length - 2;
  char* p = dest;

  for (; s < end; s += 3) {
    *p++ = tbl[s[0] >> 2];
    *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
    *p++ = tbl[((s[1] & 0xf) << 2) + (s[2] >> 6)];
    *p++ = tbl[s[2] & 0x3f];
  }

  switch (length % 3) {
    case 1:
      *p++ = tbl[s[0] >> 2];
      *p++ = tbl[(s[0] & 3) << 4];
      *p++ = '=';
      *p++ = '=';
      break;
    case 2:
      *p++ = tbl[s[0] >> 2];
      *p++ = tbl[((s[0] & 3) << 4) + (s[1] >> 4)];
      *p++ = tbl[((s[1] & 0xf) << 2)];
      *p++ = '=';
      break;
  }

  *p = '\0';
  return (size_t)(p - dest);
}

#define NEXT_CHAR(c, p)      \
  do {                       \
    c = (unsigned char)*p++; \
  } while (c_isspace(c))

#define IS_ASCII(c) (((c) & 0x80) == 0)

/*
 * Base64 decode a string back to binary data.
 *
 * @param base64: Base64-encoded string to decode
 * @param dest: Output buffer for decoded data
 * @param size: Size of output buffer
 * @return: Number of bytes decoded, or -1 on error
 */
ssize_t wget_base64_decode(const char* base64, void* dest, size_t size) {
  static const signed char base64_char_to_value[128] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                                                        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
                                                        -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
                                                        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};
#define BASE64_CHAR_TO_VALUE(c) ((int)base64_char_to_value[c])
#define IS_BASE64(c) ((IS_ASCII(c) && BASE64_CHAR_TO_VALUE(c) >= 0) || (c) == '=')

  const char* p = base64;
  unsigned char* q = dest;
  ssize_t n = 0;

  while (1) {
    unsigned char c;
    unsigned long value;

    NEXT_CHAR(c, p);
    if (!c)
      break;
    if (c == '=' || !IS_BASE64(c))
      return -1;
    value = (unsigned long)BASE64_CHAR_TO_VALUE(c) << 18;

    NEXT_CHAR(c, p);
    if (!c)
      return -1;
    if (c == '=' || !IS_BASE64(c))
      return -1;
    value |= (unsigned long)BASE64_CHAR_TO_VALUE(c) << 12;
    if (size) {
      *q++ = (unsigned char)(value >> 16);
      size--;
    }
    n++;

    NEXT_CHAR(c, p);
    if (!c)
      return -1;
    if (!IS_BASE64(c))
      return -1;

    if (c == '=') {
      NEXT_CHAR(c, p);
      if (!c)
        return -1;
      if (c != '=')
        return -1;
      continue;
    }

    value |= (unsigned long)BASE64_CHAR_TO_VALUE(c) << 6;
    if (size) {
      *q++ = (unsigned char)(0xff & (value >> 8));
      size--;
    }
    n++;

    NEXT_CHAR(c, p);
    if (!c)
      return -1;
    if (c == '=')
      continue;
    if (!IS_BASE64(c))
      return -1;

    value |= (unsigned long)BASE64_CHAR_TO_VALUE(c);
    if (size) {
      *q++ = (unsigned char)(0xff & value);
      size--;
    }
    n++;
  }

#undef IS_BASE64
#undef BASE64_CHAR_TO_VALUE

  return n;
}

#undef IS_ASCII
#undef NEXT_CHAR

#ifdef HAVE_LIBPCRE2
void* compile_pcre2_regex(const char* str) {
  int errornumber;
  PCRE2_SIZE erroroffset;
  pcre2_code* regex = pcre2_compile((PCRE2_SPTR)str, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
  if (!regex)
    fprintf(stderr, _("Invalid regular expression %s, PCRE2 error %d\n"), quote(str), errornumber);
  return regex;
}
#endif

void* compile_posix_regex(const char* str) {
  regex_t* regex = xmalloc(sizeof(regex_t));
#ifdef TESTING
  str = "a";
#endif
  int errcode = regcomp(regex, str, REG_EXTENDED | REG_NOSUB);
  if (errcode != 0) {
    size_t errbuf_size = regerror(errcode, regex, NULL, 0);
    char* errbuf = xmalloc(errbuf_size);
    regerror(errcode, regex, errbuf, errbuf_size);
    fprintf(stderr, _("Invalid regular expression %s, %s\n"), quote(str), errbuf);
    xfree(errbuf);
    xfree(regex);
    return NULL;
  }

  return regex;
}

#ifdef HAVE_LIBPCRE2
bool match_pcre2_regex(const void* regex, const char* str) {
  int rc;
  pcre2_match_data* match_data;

  match_data = pcre2_match_data_create_from_pattern(regex, NULL);

  if (match_data) {
    rc = pcre2_match(regex, (PCRE2_SPTR)str, strlen(str), 0, 0, match_data, NULL);
    pcre2_match_data_free(match_data);
  }
  else
    rc = PCRE2_ERROR_NOMEMORY;

  if (rc < 0 && rc != PCRE2_ERROR_NOMATCH)
    logprintf(LOG_VERBOSE, _("Error while matching %s: %d\n"), quote(str), rc);

  return rc >= 0;
}
#endif

bool match_posix_regex(const void* regex, const char* str) {
  int rc = regexec((const regex_t*)regex, str, 0, NULL, 0);
  if (rc == REG_NOMATCH)
    return false;
  else if (rc == 0)
    return true;
  else {
    size_t errbuf_size = regerror(rc, opt.acceptregex, NULL, 0);
    char* errbuf = xmalloc(errbuf_size);
    regerror(rc, opt.acceptregex, errbuf, errbuf_size);
    logprintf(LOG_VERBOSE, _("Error while matching %s: %d\n"), quote(str), rc);
    xfree(errbuf);
    return false;
  }
}

static void mergesort_internal(void* base, void* temp, size_t size, size_t from, size_t to, int (*cmpfun)(const void*, const void*)) {
#define ELT(array, pos) ((char*)(array) + (pos) * (size))
  if (from < to) {
    size_t i, j, k;
    size_t mid = (to + from) / 2;
    mergesort_internal(base, temp, size, from, mid, cmpfun);
    mergesort_internal(base, temp, size, mid + 1, to, cmpfun);
    i = from;
    j = mid + 1;
    for (k = from; (i <= mid) && (j <= to); k++) {
      if (cmpfun(ELT(base, i), ELT(base, j)) <= 0)
        memcpy(ELT(temp, k), ELT(base, i++), size);
      else
        memcpy(ELT(temp, k), ELT(base, j++), size);
    }
    while (i <= mid)
      memcpy(ELT(temp, k++), ELT(base, i++), size);
    while (j <= to)
      memcpy(ELT(temp, k++), ELT(base, j++), size);
    for (k = from; k <= to; k++)
      memcpy(ELT(base, k), ELT(temp, k), size);
  }
#undef ELT
}

void stable_sort(void* base, size_t nmemb, size_t size, int (*cmpfun)(const void*, const void*)) {
  if (nmemb > 1 && size > 1) {
    void* temp = xmalloc(nmemb * size);
    mergesort_internal(base, temp, size, 0, nmemb - 1, cmpfun);
    xfree(temp);
  }
}

const char* print_decimal(double number) {
  static char buf[32];
  double n = number >= 0 ? number : -number;

  if (n >= 9.95)
    snprintf(buf, sizeof buf, "%.0f", number);
  else if (n >= 0.95)
    snprintf(buf, sizeof buf, "%.1f", number);
  else if (n >= 0.001)
    snprintf(buf, sizeof buf, "%.1g", number);
  else if (n >= 0.0005)
    snprintf(buf, sizeof buf, "%.3f", number);
  else
    strcpy(buf, "0");

  return buf;
}

long get_max_length(const char* path, int length, int name) {
  long ret;
  char *p, *d;

#if !HAVE_PATHCONF
  (void)name;
#endif

  p = path ? strdupdelim(path, path + length) : xstrdup("");

  for (;;) {
    errno = 0;

#if HAVE_PATHCONF
    ret = pathconf(*p ? p : ".", name);
    if (!(ret < 0 && errno == ENOENT))
      break;
#else
    ret = PATH_MAX;
#endif

    if (!*p || strcmp(p, "/") == 0)
      break;

    d = strrchr(p, '/');
    if (d == p)
      p[1] = '\0';
    else if (d)
      *d = '\0';
    else
      *p = '\0';
  }

  xfree(p);

  if (ret < 0) {
    if (errno != 0)
      perror("pathconf");
    return 0;
  }

  return ret;
}

void wg_hex_to_string(char* str_buffer, const char* hex_buffer, size_t hex_len) {
  size_t i;

  for (i = 0; i < hex_len; i++)
    sprintf(str_buffer + 2 * i, "%02x", (unsigned)(hex_buffer[i] & 0xFF));

  str_buffer[2 * i] = '\0';
}

#ifdef HAVE_SSL

static bool wg_pubkey_pem_to_der(const char* pem, unsigned char** der, size_t* der_len) {
  char *stripped_pem, *begin_pos, *end_pos;
  size_t pem_count, stripped_pem_count = 0, pem_len;
  ssize_t size;
  unsigned char* base64data;

  *der = NULL;
  *der_len = 0;

  if (!pem)
    return false;

  begin_pos = strstr(pem, "-----BEGIN PUBLIC KEY-----");
  if (!begin_pos)
    return false;

  pem_count = (size_t)(begin_pos - pem);
  if (pem_count != 0 && pem[pem_count - 1] != '\n')
    return false;

  pem_count += 26;

  end_pos = strstr(pem + pem_count, "\n-----END PUBLIC KEY-----");
  if (!end_pos)
    return false;

  pem_len = (size_t)(end_pos - pem);

  stripped_pem = xmalloc(pem_len - pem_count + 1);

  while (pem_count < pem_len) {
    if (pem[pem_count] != '\n' && pem[pem_count] != '\r')
      stripped_pem[stripped_pem_count++] = pem[pem_count];
    ++pem_count;
  }

  stripped_pem[stripped_pem_count] = '\0';

  base64data = xmalloc(BASE64_LENGTH(stripped_pem_count));

  size = wget_base64_decode(stripped_pem, base64data, BASE64_LENGTH(stripped_pem_count));

  if (size < 0) {
    xfree(base64data);
  }
  else {
    *der = base64data;
    *der_len = (size_t)size;
  }

  xfree(stripped_pem);
  return *der_len > 0;
}

bool wg_pin_peer_pubkey(const char* pinnedpubkey, const char* pubkey, size_t pubkeylen) {
  struct file_memory* fm;
  unsigned char *buf = NULL, *pem_ptr = NULL;
  size_t size, pem_len;
  bool pem_read;
  bool result = false;

  size_t pinkeylen;
  ssize_t decoded_hash_length;
  char *pinkeycopy, *begin_pos, *end_pos;
  unsigned char *sha256sumdigest = NULL, *expectedsha256sumdigest = NULL;

  if (!pinnedpubkey)
    return true;
  if (!pubkey || !pubkeylen)
    return result;

  if (strncmp(pinnedpubkey, "sha256//", 8) == 0) {
    sha256sumdigest = xmalloc(SHA256_DIGEST_SIZE);
    sha256_buffer(pubkey, pubkeylen, sha256sumdigest);
    expectedsha256sumdigest = xmalloc(SHA256_DIGEST_SIZE);

    pinkeylen = strlen(pinnedpubkey) + 1;
    pinkeycopy = xmalloc(pinkeylen);
    memcpy(pinkeycopy, pinnedpubkey, pinkeylen);

    begin_pos = pinkeycopy;
    do {
      end_pos = strstr(begin_pos, ";sha256//");

      if (end_pos)
        end_pos[0] = '\0';

      decoded_hash_length = wget_base64_decode(begin_pos + 8, expectedsha256sumdigest, SHA256_DIGEST_SIZE);

      if (SHA256_DIGEST_SIZE == decoded_hash_length) {
        if (!memcmp(sha256sumdigest, expectedsha256sumdigest, SHA256_DIGEST_SIZE)) {
          result = true;
          break;
        }
      }
      else {
        logprintf(LOG_VERBOSE, _("Skipping key with wrong size (%d/%d): %s\n"), (int)((strlen(begin_pos + 8) * 3) / 4), SHA256_DIGEST_SIZE, quote(begin_pos + 8));
      }

      if (end_pos) {
        end_pos[0] = ';';
        begin_pos = strstr(end_pos, "sha256//");
      }
    } while (end_pos && begin_pos);

    xfree(sha256sumdigest);
    xfree(expectedsha256sumdigest);
    xfree(pinkeycopy);

    return result;
  }

  fm = wget_read_file(pinnedpubkey);
  if (!fm)
    return result;

  if (fm->length < 0 || fm->length > MAX_PINNED_PUBKEY_SIZE)
    goto cleanup;

  size = (size_t)fm->length;
  if (pubkeylen > size)
    goto cleanup;

  if (pubkeylen == size) {
    if (!memcmp(pubkey, fm->content, pubkeylen))
      result = true;
    goto cleanup;
  }

  buf = xmalloc(size + 1);
  memcpy(buf, fm->content, size);
  buf[size] = '\0';

  pem_read = wg_pubkey_pem_to_der((const char*)buf, &pem_ptr, &pem_len);
  if (!pem_read)
    goto cleanup;

  if (pubkeylen == pem_len && !memcmp(pubkey, pem_ptr, pubkeylen))
    result = true;

cleanup:
  xfree(buf);
  xfree(pem_ptr);
  wget_read_file_free(fm);

  return result;
}

#endif

#ifdef TESTING

const char* test_subdir_p(void) {
  static const struct {
    const char* d1;
    const char* d2;
    bool result;
  } test_array[] = {
      {"/somedir", "/somedir", true},
      {"/somedir", "/somedir/d2", true},
      {"/somedir/d1", "/somedir", false},
  };
  unsigned i;

  for (i = 0; i < countof(test_array); ++i) {
    bool res = subdir_p(test_array[i].d1, test_array[i].d2);
    mu_assert("test_subdir_p: wrong result", res == test_array[i].result);
  }

  return NULL;
}

const char* test_dir_matches_p(void) {
  static struct {
    const char* dirlist[3];
    const char* dir;
    bool result;
  } test_array[] = {
      {{"/somedir", "/someotherdir", NULL}, "somedir", true},
      {{"/somedir", "/someotherdir", NULL}, "anotherdir", false},
      {{"/somedir", "/*otherdir", NULL}, "anotherdir", true},
      {{"/somedir/d1", "/someotherdir", NULL}, "somedir/d1", true},
      {{"*/*d1", "/someotherdir", NULL}, "somedir/d1", true},
      {{"/somedir/d1", "/someotherdir", NULL}, "d1", false},
      {{"!COMPLETE", NULL, NULL}, "!COMPLETE", true},
      {{"*COMPLETE", NULL, NULL}, "!COMPLETE", true},
      {{"*/!COMPLETE", NULL, NULL}, "foo/!COMPLETE", true},
      {{"*COMPLETE", NULL, NULL}, "foo/!COMPLETE", false},
      {{"*/*COMPLETE", NULL, NULL}, "foo/!COMPLETE", true},
      {{"/dir with spaces", NULL, NULL}, "dir with spaces", true},
      {{"/dir*with*spaces", NULL, NULL}, "dir with spaces", true},
      {{"/Tmp/has", NULL, NULL}, "/Tmp/has space", false},
      {{"/Tmp/has", NULL, NULL}, "/Tmp/has,comma", false},
  };
  unsigned i;

  for (i = 0; i < countof(test_array); ++i) {
    bool res = dir_matches_p(test_array[i].dirlist, test_array[i].dir);
    mu_assert("test_dir_matches_p: wrong result", res == test_array[i].result);
  }

  return NULL;
}

#endif
