/* FTP Utility Functions and Common Operations
 * src/ftp-utils.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include "utils.h"
#include "url.h"
#include "retr.h"
#include "ftp.h"
#include "ssl.h"
#include "connect.h"
#include "host.h"
#include "netrc.h"
#include "convert.h"
#include "recur.h"
#include "warc.h"
#include "c-strcase.h"
#ifdef ENABLE_XATTR
#include "xattr.h"
#endif

#ifdef __VMS
#include "vms.h"
#endif

/* Create fileinfo structure */
struct fileinfo* ftp_utils_create_fileinfo(const char* name, enum ftype type, wgint size, time_t tstamp, mode_t perms) {
  struct fileinfo* f;

  if (!name) {
    return NULL;
  }

  f = xmalloc(sizeof(*f));
  f->name = xstrdup(name);
  f->type = type;
  f->size = size;
  f->tstamp = tstamp;
  f->ptype = TT_DAY; /* default parsing type */
  f->perms = perms;
  f->linkto = NULL;
  f->prev = NULL;
  f->next = NULL;

  return f;
}

/* Free single fileinfo structure */
uerr_t ftp_utils_free_fileinfo(struct fileinfo* f) {
  if (!f) {
    return FTPSYSERR;
  }

  xfree(f->name);
  xfree(f->linkto);
  xfree(f);

  return FTPOK;
}

/* Free fileinfo linked list */
uerr_t ftp_utils_free_fileinfo_list(struct fileinfo* f) {
  while (f) {
    struct fileinfo* next = f->next;
    xfree(f->name);
    xfree(f->linkto);
    xfree(f);
    f = next;
  }

  return FTPOK;
}

/* Delete fileinfo element from linked list */
struct fileinfo* ftp_utils_delete_fileinfo_element(struct fileinfo** f, struct fileinfo** start) {
  struct fileinfo* prev = (*f)->prev;
  struct fileinfo* next = (*f)->next;

  xfree((*f)->name);
  xfree((*f)->linkto);
  xfree(*f);

  if (next)
    next->prev = prev;
  if (prev)
    prev->next = next;
  else
    *start = next;

  return next;
}

/* Parse expected bytes from FTP response */
wgint ftp_utils_parse_expected_bytes(const char* s) {
  wgint res;

  while (1) {
    while (*s && *s != '(')
      ++s;
    if (!*s)
      return 0;
    ++s; /* skip the '(' */
    res = str_to_wgint(s, (char**)&s, 10);
    if (!*s)
      return 0;
    while (*s && c_isspace(*s))
      ++s;
    if (!*s)
      return 0;
    if (c_tolower(*s) != 'b')
      continue;
    if (c_strncasecmp(s, "byte", 4))
      continue;
    else
      break;
  }
  return res;
}

/* Process FTP transfer type from URL parameters */
char ftp_utils_process_transfer_type(const char* params) {
  char type_char = 'I'; /* default to binary */

  if (params) {
    if (strstr(params, "type=a") || strstr(params, "type=A"))
      type_char = 'A';
    else if (strstr(params, "type=i") || strstr(params, "type=I"))
      type_char = 'I';
    else if (strstr(params, "type=e") || strstr(params, "type=E"))
      type_char = 'E';
  }

  return type_char;
}

/* Print file length information */
uerr_t ftp_utils_print_file_length(wgint size, wgint start, bool authoritative) {
  logprintf(LOG_VERBOSE, _("Length: %s"), number_to_static_string(size));
  if (size >= 1024)
    logprintf(LOG_VERBOSE, " (%s)", human_readable(size, 10, 1));
  if (start > 0) {
    if (size - start >= 1024)
      logprintf(LOG_VERBOSE, _(", %s (%s) remaining"), number_to_static_string(size - start), human_readable(size - start, 10, 1));
    else
      logprintf(LOG_VERBOSE, _(", %s remaining"), number_to_static_string(size - start));
  }
  logputs(LOG_VERBOSE, !authoritative ? _(" (unauthoritative)\n") : "\n");

  return FTPOK;
}

/* Prepare local file for FTP transfer */
uerr_t ftp_utils_prepare_local_file(const char* local_file, wgint restval, int cmd_flags, char type_char, FILE** fp) {
  if (!local_file || !fp) {
    return FTPSYSERR;
  }

  *fp = NULL;

  /* Open the file -- if output_stream is set, use it instead.  */
  if (!output_stream || cmd_flags & DO_LIST) {
    mkalldirs(local_file);
    if (opt.backups)
      rotate_backups(local_file);

#ifdef __VMS
    int open_id;
    bool bin_type_transfer = (type_char != 'A');
    bool bin_type_file = ((!(cmd_flags & DO_LIST)) && bin_type_transfer && (opt.ftp_stmlf == 0));

    if (restval && !(cmd_flags & DO_LIST)) {
      if (bin_type_file) {
        open_id = 3;
        *fp = fopen(local_file, "ab", "fop=sqo", "acc", acc_cb, &open_id, "ctx=bin,stm", "rfm=fix", "mrs=512");
      }
      else {
        open_id = 4;
        *fp = fopen(local_file, "a", "fop=sqo", "acc", acc_cb, &open_id);
      }
    }
    else if (opt.noclobber || opt.always_rest || opt.timestamping || opt.dirstruct || opt.output_document) {
      if (opt.unlink_requested && file_exists_p(local_file, NULL)) {
        if (unlink(local_file) < 0) {
          logprintf(LOG_NOTQUIET, "%s: %s\n", local_file, strerror(errno));
          return UNLINKERR;
        }
      }

      if (bin_type_file) {
        open_id = 5;
        *fp = fopen(local_file, "wb", "fop=sqo", "acc", acc_cb, &open_id, "ctx=bin,stm", "rfm=fix", "mrs=512");
      }
      else {
        open_id = 6;
        *fp = fopen(local_file, "w", "fop=sqo", "acc", acc_cb, &open_id);
      }
    }
    else {
      *fp = fopen_excl(local_file, bin_type_file);
      if (!*fp && errno == EEXIST) {
        logprintf(LOG_NOTQUIET, _("%s has sprung into existence.\n"), local_file);
        return FOPEN_EXCL_ERR;
      }
    }
#else  /* def __VMS */
    if (restval && !(cmd_flags & DO_LIST)) {
      *fp = fopen(local_file, "ab");
    }
    else if (opt.noclobber || opt.always_rest || opt.timestamping || opt.dirstruct || opt.output_document) {
      if (opt.unlink_requested && file_exists_p(local_file, NULL)) {
        if (unlink(local_file) < 0) {
          logprintf(LOG_NOTQUIET, "%s: %s\n", local_file, strerror(errno));
          return UNLINKERR;
        }
      }
      *fp = fopen(local_file, "wb");
    }
    else {
      *fp = fopen_excl(local_file, true);
      if (!*fp && errno == EEXIST) {
        logprintf(LOG_NOTQUIET, _("%s has sprung into existence.\n"), local_file);
        return FOPEN_EXCL_ERR;
      }
    }
#endif /* def __VMS [else] */

    if (!*fp) {
      logprintf(LOG_NOTQUIET, "%s: %s\n", local_file, strerror(errno));
      return FOPENERR;
    }
  }
  else
    *fp = output_stream;

  return FTPOK;
}

/* Finalize local file after FTP transfer */
uerr_t ftp_utils_finalize_local_file(const char* local_file, struct fileinfo* f, bool downloaded, wgint qtyread) {
  const char* actual_target = NULL;

  if (!local_file) {
    return FTPSYSERR;
  }

  set_local_file(&actual_target, local_file);

  /* If downloading a plain file, and the user requested it, then
     set valid (non-zero) permissions. */
  if (downloaded && (actual_target != NULL) && f && f->type == FT_PLAINFILE && opt.preserve_perm) {
    if (f->perms) {
      if (chmod(actual_target, f->perms))
        logprintf(LOG_NOTQUIET, _("Failed to set permissions for %s.\n"), actual_target);
    }
    else
      DEBUGP(("Unrecognized permissions for %s.\n", actual_target));
  }

  /* Set the time-stamp information to the local file.  Symlinks
     are not to be stamped because it sets the stamp on the
     original.  :( */
  if (actual_target != NULL) {
    if (opt.useservertimestamps && !(f && f->type == FT_SYMLINK && !opt.retr_symlinks) && f && f->tstamp != -1 && downloaded && file_exists_p(local_file, NULL)) {
      touch(actual_target, f->tstamp);
    }
    else if (f && f->tstamp == -1)
      logprintf(LOG_NOTQUIET, _("%s: corrupt time-stamp.\n"), actual_target);
  }

  /* Update download statistics */
  if (downloaded && !opt.spider) {
    downloaded_file(FILE_DOWNLOADED_NORMALLY, local_file);
  }

  return FTPOK;
}

/* Set file permissions */
uerr_t ftp_utils_set_file_permissions(const char* local_file, mode_t perms) {
  if (!local_file) {
    return FTPSYSERR;
  }

  if (perms && opt.preserve_perm) {
    if (chmod(local_file, perms))
      logprintf(LOG_NOTQUIET, _("Failed to set permissions for %s.\n"), local_file);
  }

  return FTPOK;
}

/* Set file timestamp */
uerr_t ftp_utils_set_file_timestamp(const char* local_file, time_t tstamp) {
  if (!local_file) {
    return FTPSYSERR;
  }

  if (tstamp != -1 && opt.useservertimestamps && file_exists_p(local_file, NULL)) {
    touch(local_file, tstamp);
  }
  else if (tstamp == -1)
    logprintf(LOG_NOTQUIET, _("%s: corrupt time-stamp.\n"), local_file);

  return FTPOK;
}

/* Build target filename from URL */
char* ftp_utils_build_target_filename(struct url* u, struct url* original_url) {
  if (!u) {
    return NULL;
  }

  return url_file_name(opt.trustservernames || !original_url ? u : original_url, NULL);
}

/* Merge directory paths */
char* ftp_utils_merge_directory_path(const char* base, const char* subdir) {
  if (!base || !subdir) {
    return NULL;
  }

  return file_merge(base, subdir);
}

/* Validate URL path for FTP operations */
uerr_t ftp_utils_validate_url_path(struct url* u) {
  if (!u) {
    return FTPSYSERR;
  }

  /* Basic validation - ensure URL has necessary components */
  if (!u->host || !u->path) {
    return FTPSYSERR;
  }

  return FTPOK;
}

/* Print retry message */
uerr_t ftp_utils_print_retry_message(int count, int max_tries) {
  if (max_tries && (count < max_tries)) {
    logprintf(LOG_VERBOSE, _("Retrying.\n"));
  }

  return FTPOK;
}

/* Get error string for FTP error code */
const char* ftp_utils_error_string(uerr_t err) {
  switch (err) {
    case FTPOK:
      return "FTP operation completed successfully";
    case FTPRERR:
      return "FTP server response error";
    case FTPSRVERR:
      return "FTP server error";
    case FTPNOPASV:
      return "FTP passive mode not supported";
    case FTPINVPASV:
      return "Invalid FTP passive response";
    case FTPPORTERR:
      return "FTP port command error";
    case FTPLOGREFUSED:
      return "FTP login refused";
    case FTPLOGINC:
      return "FTP login incorrect";
    case FTPNSFOD:
      return "FTP file or directory not found";
    case FTPUNKNOWNTYPE:
      return "Unknown FTP transfer type";
    case FTPNOPBSZ:
      return "FTP PBSZ command not supported";
    case FTPNOPROT:
      return "FTP PROT command not supported";
    case FTPNOAUTH:
      return "FTP AUTH command not supported";
    case FTPRESTFAIL:
      return "FTP REST command failed";
    case FTPSYSERR:
      return "FTP system error";
    default:
      return "Unknown FTP error";
  }
}

/* Handle common FTP errors */
uerr_t ftp_utils_handle_common_errors(uerr_t err, int* should_retry) {
  if (!should_retry) {
    return FTPSYSERR;
  }

  *should_retry = 0;

  switch (err) {
    case CONSOCKERR:
    case CONERROR:
    case FTPSRVERR:
    case FTPRERR:
    case WRITEFAILED:
    case FTPUNKNOWNTYPE:
    case FTPSYSERR:
    case FTPPORTERR:
    case FTPLOGREFUSED:
    case FTPINVPASV:
    case FOPEN_EXCL_ERR:
      *should_retry = 1;
      break;
    default:
      *should_retry = 0;
      break;
  }

  return FTPOK;
}

/* Get server greeting */
uerr_t ftp_utils_get_server_greeting(int csock) {
  uerr_t err = 0;

  /* Get the server's greeting */
  err = ftp_greeting(csock);
  if (err != FTPOK) {
    logputs(LOG_NOTQUIET, "Error in server response. Closing.\n");
    fd_close(csock);
  }

  return err;
}

/* Get system type from FTP server */
uerr_t ftp_utils_get_system_type(int csock, enum stype* server_type, enum ustype* unix_type) {
  if (!csock || !server_type || !unix_type) {
    return FTPSYSERR;
  }

  return ftp_syst(csock, server_type, unix_type);
}

/* Set FTP transfer type */
uerr_t ftp_utils_set_transfer_type(int csock, char type_char) {
  if (!csock) {
    return FTPSYSERR;
  }

  return ftp_type(csock, type_char);
}

/* Check if scheme is secure */
bool ftp_utils_is_secure_scheme(enum url_scheme scheme) {
  return (scheme == SCHEME_FTPS);
}

/* Validate security options */
uerr_t ftp_utils_validate_security_options(struct url* u) {
  if (!u) {
    return FTPSYSERR;
  }

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_FTPS) {
    if (!ssl_init()) {
      scheme_disable(SCHEME_FTPS);
      logprintf(LOG_NOTQUIET, _("Could not initialize SSL. It will be disabled.\n"));
      return SSLINITFAILED;
    }
  }
#endif

  return FTPOK;
}

/* Update download statistics */
uerr_t ftp_utils_update_download_stats(wgint bytes_downloaded, double download_time) {
  total_downloaded_bytes += bytes_downloaded;
  total_download_time += download_time;
  numurls++;

  return FTPOK;
}

/* Format download rate */
const char* ftp_utils_format_download_rate(wgint bytes, double seconds) {
  return retr_rate(bytes, seconds);
}