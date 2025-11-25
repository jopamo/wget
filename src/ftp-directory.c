/* FTP Directory Navigation and Listing Implementation
 * src/ftp-directory.c
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

/* File where the "ls -al" listing will be saved.  */
#ifdef MSDOS
#define LIST_FILENAME "_listing"
#else
#define LIST_FILENAME ".listing"
#endif

/* Initialize directory context */
uerr_t ftp_directory_init_context(ftp_directory_ctx_t* dir_ctx, enum stype system_type) {
  if (!dir_ctx) {
    return FTPSYSERR;
  }

  dir_ctx->current_dir = NULL;
  dir_ctx->initial_dir = NULL;
  dir_ctx->target_dir = NULL;
  dir_ctx->server_type = system_type;
  dir_ctx->unix_type = UST_OTHER;
  dir_ctx->avoid_list_a = false;
  dir_ctx->avoid_list = false;
  dir_ctx->list_a_check_done = false;
  dir_ctx->cwd_flags = 0;

  return FTPOK;
}

/* Set directory context from session */
uerr_t ftp_directory_set_context(ftp_directory_ctx_t* dir_ctx, ftp_session_t* session) {
  if (!dir_ctx || !session) {
    return FTPSYSERR;
  }

  xfree(dir_ctx->current_dir);
  xfree(dir_ctx->initial_dir);
  xfree(dir_ctx->target_dir);

  if (session->id) {
    dir_ctx->initial_dir = xstrdup(session->id);
    dir_ctx->current_dir = xstrdup(session->id);
  }

  if (session->target) {
    dir_ctx->target_dir = xstrdup(session->target);
  }

  dir_ctx->server_type = session->rs;
  dir_ctx->unix_type = session->rsu;

  /* Set list command preferences based on system type */
  switch (session->rs) {
    case ST_VMS:
      /* About ST_VMS there is an old note:
         2008-01-29  SMS.  For a VMS FTP server, where "LIST -a" may not
         fail, but will never do what is desired here,
         skip directly to the simple "LIST" command
         (assumed to be the last one in the list).  */
      DEBUGP(("\nVMS: I know it and I will use \"LIST\" as standard list command\n"));
      dir_ctx->list_a_check_done = true;
      dir_ctx->avoid_list_a = true;
      break;
    case ST_UNIX:
      if (session->rsu == UST_MULTINET) {
        DEBUGP(
            ("\nUNIX MultiNet: I know it and I will use \"LIST\" "
             "as standard list command\n"));
        dir_ctx->list_a_check_done = true;
        dir_ctx->avoid_list_a = true;
      }
      else if (session->rsu == UST_TYPE_L8) {
        DEBUGP(
            ("\nUNIX TYPE L8: I know it and I will use \"LIST -a\" "
             "as standard list command\n"));
        dir_ctx->list_a_check_done = true;
        dir_ctx->avoid_list = true;
      }
      break;
    default:
      break;
  }

  return FTPOK;
}

/* Change working directory */
uerr_t ftp_directory_change_directory(int csock, const char* target_dir, const char* initial_dir, enum stype server_type) {
  const char* targ = NULL;
  char* target = (char*)target_dir;
  char targetbuf[1024];
  int cwd_count;
  int cwd_end;
  int cwd_start;
  uerr_t err;

  if (!csock || !target_dir) {
    return FTPSYSERR;
  }

  if (!*target_dir)
    logputs(LOG_VERBOSE, _("==> CWD not needed.\n"));
  else {
    DEBUGP(("changing working directory\n"));

    /* Change working directory.  To change to a non-absolute
       Unix directory, we need to prepend initial directory
       (initial_dir) to it.  Absolute directories "just work".

       A relative directory is one that does not begin with '/'
       and, on non-Unix OS'es, one that doesn't begin with
       "[a-z]:".

       This is not done for OS400, which doesn't use
       "/"-delimited directories, nor does it support directory
       hierarchies.  "CWD foo" followed by "CWD bar" leaves us
       in "bar", not in "foo/bar", as would be customary
       elsewhere.  */

    if (target[0] != '/' && !(server_type != ST_UNIX && c_isalpha(target[0]) && target[1] == ':') && (server_type != ST_OS400) && (server_type != ST_VMS)) {
      char *ntarget, *p;
      size_t idlen = strlen(initial_dir);
      size_t len;

      /* Strip trailing slash(es) from initial_dir. */
      while (idlen > 0 && initial_dir[idlen - 1] == '/')
        --idlen;

      len = idlen + 1 + strlen(target);
      if (len < sizeof(targetbuf))
        p = ntarget = targetbuf;
      else
        p = ntarget = xmalloc(len + 1);

      memcpy(p, initial_dir, idlen);
      p += idlen;
      *p++ = '/';
      strcpy(p, target);

      DEBUGP(("Prepended initial PWD to relative path:\n"));
      DEBUGP(("   pwd: '%s'\n   old: '%s'\n  new: '%s'\n", initial_dir, target, ntarget));
      target = ntarget;
    }

    /* Decide on one pass (absolute) or two (relative).
       The VMS restriction may be relaxed when the squirrely code
       above is reformed.
    */
    if ((server_type == ST_VMS) && (target[0] != '/')) {
      cwd_start = 0;
      DEBUGP(("Using two-step CWD for relative path.\n"));
    }
    else {
      /* Go straight to the target. */
      cwd_start = 1;
    }

    /* At least one VMS FTP server (TCPware V5.6-2) can switch to
       a UNIX emulation mode when given a UNIX-like directory
       specification (like "a/b/c").  If allowed to continue this
       way, LIST interpretation will be confused, because the
       system type (SYST response) will not be re-checked, and
       future UNIX-format directory listings (for multiple URLs or
       "-r") will be horribly misinterpreted.

       The cheap and nasty work-around is to do a "CWD []" after a
       UNIX-like directory specification is used.  (A single-level
       directory is harmless.)  This puts the TCPware server back
       into VMS mode, and does no harm on other servers.

       Unlike the rest of this block, this particular behavior
       _is_ VMS-specific, so it gets its own VMS test.
    */
    if ((server_type == ST_VMS) && (strchr(target, '/') != NULL)) {
      cwd_end = 3;
      DEBUGP(("Using extra \"CWD []\" step for VMS server.\n"));
    }
    else {
      cwd_end = 2;
    }

    for (cwd_count = cwd_start; cwd_count < cwd_end; cwd_count++) {
      switch (cwd_count) {
        case 0:
          /* Step one (optional): Go to the initial directory,
             exactly as reported by the server.
          */
          targ = initial_dir;
          break;

        case 1:
          /* Step two: Go to the target directory.  (Absolute or
             relative will work now.)
          */
          targ = target;
          break;

        case 2:
          /* Step three (optional): "CWD []" to restore server
             VMS-ness.
          */
          targ = "[]";
          break;

        default:
          logprintf(LOG_ALWAYS, _("Logically impossible section reached in getftp()"));
          logprintf(LOG_ALWAYS, _("cwd_count: %d\ncwd_start: %d\ncwd_end: %d\n"), cwd_count, cwd_start, cwd_end);
          abort();
      }

      if (!opt.server_response)
        logprintf(LOG_VERBOSE, "==> CWD (%d) %s ... ", cwd_count, quotearg_style(escape_quoting_style, target));

      err = ftp_cwd(csock, targ);

      /* FTPRERR, WRITEFAILED, FTPNSFOD */
      switch (err) {
        case FTPRERR:
          logputs(LOG_VERBOSE, "\n");
          logputs(LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
          fd_close(csock);
          return err;
        case WRITEFAILED:
          logputs(LOG_VERBOSE, "\n");
          logputs(LOG_NOTQUIET, _("Write failed, closing control connection.\n"));
          fd_close(csock);
          return err;
        case FTPNSFOD:
          logputs(LOG_VERBOSE, "\n");
          logprintf(LOG_NOTQUIET, _("No such directory %s.\n\n"), quote(target_dir));
          fd_close(csock);
          return err;
        case FTPOK:
          break;
        default:
          abort();
      }

      if (!opt.server_response)
        logputs(LOG_VERBOSE, _("done.\n"));

    } /* for */

    if (target != target_dir && target != targetbuf)
      xfree(target);

  } /* else */

  return FTPOK;
}

/* Get directory listing */
uerr_t ftp_directory_get_listing(struct url* u, struct url* original_url, ftp_session_t* session, struct fileinfo** file_list) {
  uerr_t err;
  char* uf; /* url file name */
  char* lf; /* list file name */
  char* old_target = session->target;

  if (!u || !session || !file_list) {
    return FTPSYSERR;
  }

  session->st &= ~ON_YOUR_OWN;
  session->cmd |= (DO_LIST | LEAVE_PENDING);
  session->cmd &= ~DO_RETR;

  /* Find the listing file name.  We do it by taking the file name of
     the URL and replacing the last component with the listing file
     name.  */
  uf = url_file_name(u, NULL);
  lf = file_merge(uf, LIST_FILENAME);
  xfree(uf);
  DEBUGP((_("Using %s as listing tmp file.\n"), quote(lf)));

  session->target = xstrdup(lf);
  xfree(lf);
  /* Note: This function needs to be implemented using public FTP API */
  /* Original call was to internal ftp_loop_internal */
  err = FTPSYSERR;
  lf = xstrdup(session->target);
  xfree(session->target);
  session->target = old_target;

  if (err == RETROK) {
    *file_list = ftp_parse_ls(lf, session->rs);
    if (opt.remove_listing) {
      if (unlink(lf))
        logprintf(LOG_NOTQUIET, "unlink: %s\n", strerror(errno));
      else
        logprintf(LOG_VERBOSE, _("Removed %s.\n"), quote(lf));
    }
  }
  else
    *file_list = NULL;
  xfree(lf);
  session->cmd &= ~DO_LIST;
  return err;
}

/* Process directory listing and update list command preferences */
uerr_t ftp_directory_process_listing(ftp_directory_ctx_t* dir_ctx, wgint rd_size, wgint previous_rd_size, bool list_a_used) {
  if (!dir_ctx) {
    return FTPSYSERR;
  }

  /* 2013-10-17 Andrea Urbani (matfanjol)
     < __LIST_A_EXPLANATION__ >
      After the SYST command, looks if it knows that system.
      If yes, wget will force the use of "LIST" or "LIST -a".
      If no, wget will try, only the first time of each session, before the
      "LIST -a" command and after the "LIST".
      If "LIST -a" works and returns more or equal data of the "LIST",
      "LIST -a" will be the standard list command for all the session.
      If "LIST -a" fails or returns less data than "LIST" (think on the case
      of an existing file called "-a"), "LIST" will be the standard list
      command for all the session.
      ("LIST -a" is used to get also the hidden files)

      */
  if (!dir_ctx->list_a_check_done) {
    /* We still have to check "LIST" after the first "LIST -a" to see
       if with "LIST" we get more data than "LIST -a", that means
       "LIST -a" returned files/folders with "-a" name. */
    if (dir_ctx->avoid_list_a) {
      /* LIST was used in this cycle.
         Let's see the result. */
      if (rd_size > previous_rd_size) {
        /* LIST returns more data than "LIST -a".
           "LIST" is the official command to use. */
        dir_ctx->list_a_check_done = true;
        DEBUGP(
            ("LIST returned more data than \"LIST -a\": "
             "I will use \"LIST\" as standard list command\n"));
      }
      else if (previous_rd_size > rd_size) {
        /* "LIST -a" returned more data then LIST.
           "LIST -a" is the official command to use. */
        dir_ctx->list_a_check_done = true;
        dir_ctx->avoid_list = true;
        dir_ctx->avoid_list_a = false;
        DEBUGP(
            ("LIST returned less data than \"LIST -a\": I will "
             "use \"LIST -a\" as standard list command\n"));
      }
      else {
        /* LIST and "LIST -a" return the same data. */
        if (rd_size == 0) {
          /* Same empty data. We will check both again because
             we cannot check if "LIST -a" has returned an empty
             folder instead of a folder content. */
          dir_ctx->avoid_list_a = false;
        }
        else {
          /* Same data, so, better to take "LIST -a" that
             shows also hidden files/folders (when present) */
          dir_ctx->list_a_check_done = true;
          dir_ctx->avoid_list = true;
          dir_ctx->avoid_list_a = false;
          DEBUGP(
              ("LIST returned the same amount of data of "
               "\"LIST -a\": I will use \"LIST -a\" as standard "
               "list command\n"));
        }
      }
    }
    else {
      /* In this cycle "LIST -a" should being used. Is it true? */
      if (list_a_used) {
        /* Yes, it is.
           OK, let's save the amount of data and try again
           with LIST */
        dir_ctx->avoid_list_a = true;
        DEBUGP(("Saved LIST -a data size: %" PRId64 "\n", rd_size));
      }
      else {
        /* No: something happens and LIST was used.
           This means "LIST -a" raises an error. */
        dir_ctx->list_a_check_done = true;
        dir_ctx->avoid_list_a = true;
        DEBUGP(
            ("\"LIST -a\" failed: I will use \"LIST\" "
             "as standard list command\n"));
      }
    }
  }

  return FTPOK;
}

/* Check if directory name is insecure */
bool ftp_directory_is_insecure_name(const char* s) {
  if (*s == '/')
    return true;

  if (strstr(s, "../") != 0)
    return true;

  return false;
}

/* Check if fileinfo entry is invalid */
bool ftp_directory_is_invalid_entry(struct fileinfo* f) {
  struct fileinfo* cur = f;
  char* f_name = f->name;

  /* If the node we're currently checking has a duplicate later, we eliminate
   * the current node and leave the next one intact. */
  while (cur->next) {
    cur = cur->next;
    if (strcmp(f_name, cur->name) == 0)
      return true;
  }
  return false;
}

/* Cleanup directory context */
uerr_t ftp_directory_cleanup(ftp_directory_ctx_t* dir_ctx) {
  if (!dir_ctx) {
    return FTPSYSERR;
  }

  xfree(dir_ctx->current_dir);
  xfree(dir_ctx->initial_dir);
  xfree(dir_ctx->target_dir);
  dir_ctx->current_dir = NULL;
  dir_ctx->initial_dir = NULL;
  dir_ctx->target_dir = NULL;
  dir_ctx->server_type = ST_UNIX;
  dir_ctx->unix_type = UST_OTHER;
  dir_ctx->avoid_list_a = false;
  dir_ctx->avoid_list = false;
  dir_ctx->list_a_check_done = false;

  return FTPOK;
}