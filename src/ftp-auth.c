/* FTP Authentication and Login Implementation
 * src/ftp-auth.c
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

/* Initialize authentication context */
uerr_t ftp_auth_init_context(ftp_auth_ctx_t* auth_ctx, struct url* u) {
  if (!auth_ctx) {
    return FTPSYSERR;
  }

  auth_ctx->user = NULL;
  auth_ctx->passwd = NULL;
  auth_ctx->using_control_security = false;
  auth_ctx->using_data_security = false;
  auth_ctx->proxy = NULL;
  auth_ctx->logged_in = false;

  return FTPOK;
}

/* Set authentication credentials */
uerr_t ftp_auth_set_credentials(ftp_auth_ctx_t* auth_ctx, const char* user, const char* passwd) {
  if (!auth_ctx) {
    return FTPSYSERR;
  }

  xfree(auth_ctx->user);
  xfree(auth_ctx->passwd);

  if (user) {
    auth_ctx->user = xstrdup(user);
  }
  else {
    auth_ctx->user = NULL;
  }

  if (passwd) {
    auth_ctx->passwd = xstrdup(passwd);
  }
  else {
    auth_ctx->passwd = NULL;
  }

  return FTPOK;
}

/* Get authentication credentials from URL and options */
uerr_t ftp_auth_get_credentials(struct url* u, const char** user, const char** passwd) {
  if (!u) {
    return FTPSYSERR;
  }

  /* Find the username with priority */
  if (u->user)
    *user = u->user;
  else if (opt.user && (opt.use_askpass || opt.ask_passwd))
    *user = opt.user;
  else if (opt.ftp_user)
    *user = opt.ftp_user;
  else if (opt.user)
    *user = opt.user;
  else
    *user = NULL;

  /* Find the password with priority */
  if (u->passwd)
    *passwd = u->passwd;
  else if (opt.passwd && (opt.use_askpass || opt.ask_passwd))
    *passwd = opt.passwd;
  else if (opt.ftp_passwd)
    *passwd = opt.ftp_passwd;
  else if (opt.passwd)
    *passwd = opt.passwd;
  else
    *passwd = NULL;

  /* Check for ~/.netrc if none of the above match */
  if (opt.netrc && (!*user || !*passwd))
    search_netrc(u->host, user, passwd, 1, NULL);

  if (!*user)
    *user = "anonymous";
  if (!*passwd)
    *passwd = "-wget@";

  return FTPOK;
}

/* Perform FTP login sequence */
uerr_t ftp_auth_perform_login(int csock, struct url* u, struct url* proxy, const char* user, const char* passwd, bool* using_control_security) {
  uerr_t err;
  char* logname = NULL;

  if (!csock || !u || !using_control_security) {
    return FTPSYSERR;
  }

  *using_control_security = false;

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_FTPS) {
    /* Initialize SSL layer first */
    if (!ssl_init()) {
      scheme_disable(SCHEME_FTPS);
      logprintf(LOG_NOTQUIET, _("Could not initialize SSL. It will be disabled.\n"));
      return SSLINITFAILED;
    }

    /* If we're using the default FTP port and implicit FTPS was requested,
     * rewrite the port to the default *implicit* FTPS port.
     */
    if (opt.ftps_implicit && u->port == DEFAULT_FTP_PORT) {
      DEBUGP(("Implicit FTPS was specified. Rewriting default port to %d.\n", DEFAULT_FTPS_IMPLICIT_PORT));
      u->port = DEFAULT_FTPS_IMPLICIT_PORT;
    }
  }
#endif

  /* Login with proper USER/PASS sequence.  */
  logprintf(LOG_VERBOSE, _("Logging in as %s ... "), quotearg_style(escape_quoting_style, user));
  if (opt.server_response)
    logputs(LOG_ALWAYS, "\n");

  if (proxy) {
    /* If proxy is in use, log in as username@target-site. */
    logname = concat_strings(user, "@", u->host, (char*)0);
    err = ftp_login(csock, logname, passwd);
    xfree(logname);
  }
  else
    err = ftp_login(csock, user, passwd);

  /* FTPRERR, FTPSRVERR, WRITEFAILED, FTPLOGREFUSED, FTPLOGINC */
  switch (err) {
    case FTPRERR:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
      fd_close(csock);
      return err;
    case FTPSRVERR:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("Error in server greeting.\n"));
      fd_close(csock);
      return err;
    case WRITEFAILED:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("Write failed, closing control connection.\n"));
      fd_close(csock);
      return err;
    case FTPLOGREFUSED:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("The server refuses login.\n"));
      fd_close(csock);
      return FTPLOGREFUSED;
    case FTPLOGINC:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("Login incorrect.\n"));
      fd_close(csock);
      return FTPLOGINC;
    case FTPOK:
      if (!opt.server_response)
        logputs(LOG_VERBOSE, _("Logged in!\n"));
      break;
    default:
      abort();
  }

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_FTPS) {
    /* Send the PBSZ and PROT commands, in that order.
     * If we are here it means that the server has already accepted
     * some form of FTPS. Thus, these commands must work.
     * If they don't work, that's an error. There's no sense in honoring
     * --ftps-fallback-to-ftp or similar options. */
    enum prot_level prot = (opt.ftps_clear_data_connection ? PROT_CLEAR : PROT_PRIVATE);

    if (!opt.server_response)
      logputs(LOG_VERBOSE, "==> PBSZ 0 ... ");
    if ((err = ftp_pbsz(csock, 0)) == FTPNOPBSZ) {
      logputs(LOG_NOTQUIET, _("Server did not accept the 'PBSZ 0' command.\n"));
      return err;
    }
    if (!opt.server_response)
      logputs(LOG_VERBOSE, "done.");

    if (!opt.server_response)
      logprintf(LOG_VERBOSE, "  ==> PROT %c ... ", (int)prot);
    if ((err = ftp_prot(csock, prot)) == FTPNOPROT) {
      logprintf(LOG_NOTQUIET, _("Server did not accept the 'PROT %c' command.\n"), (int)prot);
      return err;
    }
    if (!opt.server_response)
      logputs(LOG_VERBOSE, "done.\n");

    if (prot != PROT_CLEAR) {
      *using_control_security = true;
    }
  }
#endif

  return FTPOK;
}

/* Initialize SSL/TLS for control connection */
uerr_t ftp_auth_init_control_ssl(int csock, struct url* u, bool* using_control_security) {
#ifdef HAVE_SSL
  bool using_security = false;

  if (!csock || !u || !using_control_security) {
    return FTPSYSERR;
  }

  /* If '--ftps-implicit' was passed, perform the SSL handshake directly,
   * and do not send an AUTH command.
   * Otherwise send an AUTH sequence before login,
   * and perform the SSL handshake if accepted by server.
   */
  if (!opt.ftps_implicit && !opt.server_response)
    logputs(LOG_VERBOSE, "==> AUTH TLS ... ");
  if (opt.ftps_implicit || ftp_auth(csock, SCHEME_FTPS) == FTPOK) {
    if (!ssl_connect_wget(csock, u->host, NULL)) {
      fd_close(csock);
      return CONSSLERR;
    }
    else if (!ssl_check_certificate(csock, u->host)) {
      fd_close(csock);
      return VERIFCERTERR;
    }

    if (!opt.ftps_implicit && !opt.server_response)
      logputs(LOG_VERBOSE, " done.\n");

    /* If implicit FTPS was requested, we act as "normal" FTP, but over SSL.
     * We're not using RFC 2228 commands.
     */
    using_security = true;
  }
  else {
    /* The server does not support 'AUTH TLS'.
     * Check if --ftps-fallback-to-ftp was passed. */
    if (opt.ftps_fallback_to_ftp) {
      logputs(LOG_NOTQUIET, "Server does not support AUTH TLS. Falling back to FTP.\n");
      using_security = false;
    }
    else {
      fd_close(csock);
      return FTPNOAUTH;
    }
  }

  *using_control_security = using_security;
  return NOCONERROR;
#else
  return FTPSYSERR;
#endif
}

/* Get FTP server greeting */
uerr_t ftp_auth_get_greeting(int csock) {
  uerr_t err = 0;

  /* Get the server's greeting */
  err = ftp_greeting(csock);
  if (err != FTPOK) {
    logputs(LOG_NOTQUIET, "Error in server response. Closing.\n");
    fd_close(csock);
  }

  return err;
}

/* Get FTP server system type */
uerr_t ftp_auth_get_system_type(int csock, enum stype* server_type, enum ustype* unix_type) {
  uerr_t err;

  if (!csock || !server_type || !unix_type) {
    return FTPSYSERR;
  }

  if (!opt.server_response)
    logprintf(LOG_VERBOSE, "==> SYST ... ");
  err = ftp_syst(csock, server_type, unix_type);
  /* FTPRERR */
  switch (err) {
    case FTPRERR:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
      fd_close(csock);
      return err;
    case FTPSRVERR:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("Server error, can't determine system type.\n"));
      break;
    case FTPOK:
      /* Everything is OK.  */
      break;
    default:
      abort();
  }
  if (!opt.server_response && err != FTPSRVERR)
    logputs(LOG_VERBOSE, _("done.    "));

  return err;
}

/* Get FTP server initial directory */
uerr_t ftp_auth_get_initial_directory(int csock, char** initial_dir) {
  uerr_t err;

  if (!csock || !initial_dir) {
    return FTPSYSERR;
  }

  if (!opt.server_response)
    logprintf(LOG_VERBOSE, "==> PWD ... ");
  err = ftp_pwd(csock, initial_dir);
  /* FTPRERR */
  switch (err) {
    case FTPRERR:
      logputs(LOG_VERBOSE, "\n");
      logputs(LOG_NOTQUIET, _("\
Error in server response, closing control connection.\n"));
      fd_close(csock);
      return err;
    case FTPSRVERR:
      /* PWD unsupported -- assume "/". */
      xfree(*initial_dir);
      *initial_dir = xstrdup("/");
      break;
    case FTPOK:
      /* Everything is OK.  */
      break;
    default:
      abort();
  }

  if (!opt.server_response)
    logputs(LOG_VERBOSE, _("done.\n"));

  return err;
}

/* Set FTP transfer type */
uerr_t ftp_auth_set_transfer_type(int csock, char type_char) {
  uerr_t err;

  if (!csock) {
    return FTPSYSERR;
  }

  if (!opt.server_response)
    logprintf(LOG_VERBOSE, "==> TYPE %c ... ", type_char);
  err = ftp_type(csock, type_char);
  /* FTPRERR, WRITEFAILED, FTPUNKNOWNTYPE */
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
    case FTPUNKNOWNTYPE:
      logputs(LOG_VERBOSE, "\n");
      logprintf(LOG_NOTQUIET, _("Unknown type `%c', closing control connection.\n"), type_char);
      fd_close(csock);
      return err;
    case FTPOK:
      /* Everything is OK.  */
      break;
    default:
      abort();
  }
  if (!opt.server_response)
    logputs(LOG_VERBOSE, _("done.  "));

  return err;
}

/* Cleanup authentication context */
uerr_t ftp_auth_cleanup(ftp_auth_ctx_t* auth_ctx) {
  if (!auth_ctx) {
    return FTPSYSERR;
  }

  xfree(auth_ctx->user);
  xfree(auth_ctx->passwd);
  auth_ctx->user = NULL;
  auth_ctx->passwd = NULL;
  auth_ctx->using_control_security = false;
  auth_ctx->using_data_security = false;
  auth_ctx->proxy = NULL;

  return FTPOK;
}