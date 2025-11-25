/* FTP Session Management Implementation
 * src/ftp-session.c
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

/* Initialize FTP session */
uerr_t ftp_session_init(ftp_session_t* session, struct url* proxy) {
  if (!session) {
    return FTPSYSERR;
  }

  session->csock = -1;
  session->dtsock = -1;
  session->local_sock = -1;
  session->rs = ST_UNIX;
  session->rsu = UST_OTHER;
  session->id = NULL;
  session->target = NULL;
  session->proxy = proxy;
  session->st = 0;
  session->cmd = 0;
  session->dltime = 0.0;

  return FTPOK;
}

/* Note: ccon is an internal structure used only within ftp.c */

/* Set session target */
uerr_t ftp_session_set_target(ftp_session_t* session, const char* target) {
  if (!session) {
    return FTPSYSERR;
  }

  xfree(session->target);
  if (target) {
    session->target = xstrdup(target);
  }
  else {
    session->target = NULL;
  }

  return FTPOK;
}

/* Set session initial directory */
uerr_t ftp_session_set_initial_directory(ftp_session_t* session, const char* initial_dir) {
  if (!session) {
    return FTPSYSERR;
  }

  xfree(session->id);
  if (initial_dir) {
    session->id = xstrdup(initial_dir);
  }
  else {
    session->id = NULL;
  }

  return FTPOK;
}

/* Set session system type */
uerr_t ftp_session_set_system_type(ftp_session_t* session, enum stype server_type, enum ustype unix_type) {
  if (!session) {
    return FTPSYSERR;
  }

  session->rs = server_type;
  session->rsu = unix_type;

  return FTPOK;
}

/* Set session command flags */
uerr_t ftp_session_set_commands(ftp_session_t* session, int cmd_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->cmd = cmd_flags;

  return FTPOK;
}

/* Add command flags to session */
uerr_t ftp_session_add_commands(ftp_session_t* session, int cmd_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->cmd |= cmd_flags;

  return FTPOK;
}

/* Remove command flags from session */
uerr_t ftp_session_remove_commands(ftp_session_t* session, int cmd_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->cmd &= ~cmd_flags;

  return FTPOK;
}

/* Set session status flags */
uerr_t ftp_session_set_status(ftp_session_t* session, int status_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->st = status_flags;

  return FTPOK;
}

/* Add status flags to session */
uerr_t ftp_session_add_status(ftp_session_t* session, int status_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->st |= status_flags;

  return FTPOK;
}

/* Remove status flags from session */
uerr_t ftp_session_remove_status(ftp_session_t* session, int status_flags) {
  if (!session) {
    return FTPSYSERR;
  }

  session->st &= ~status_flags;

  return FTPOK;
}

/* Check if session has specific command flags */
bool ftp_session_has_commands(ftp_session_t* session, int cmd_flags) {
  if (!session) {
    return false;
  }

  return (session->cmd & cmd_flags) == cmd_flags;
}

/* Check if session has specific status flags */
bool ftp_session_has_status(ftp_session_t* session, int status_flags) {
  if (!session) {
    return false;
  }

  return (session->st & status_flags) == status_flags;
}

/* Set session control socket */
uerr_t ftp_session_set_control_socket(ftp_session_t* session, int csock) {
  if (!session) {
    return FTPSYSERR;
  }

  session->csock = csock;

  return FTPOK;
}

/* Set session data socket */
uerr_t ftp_session_set_data_socket(ftp_session_t* session, int dtsock) {
  if (!session) {
    return FTPSYSERR;
  }

  session->dtsock = dtsock;

  return FTPOK;
}

/* Set session local socket */
uerr_t ftp_session_set_local_socket(ftp_session_t* session, int local_sock) {
  if (!session) {
    return FTPSYSERR;
  }

  session->local_sock = local_sock;

  return FTPOK;
}

/* Set session download time */
uerr_t ftp_session_set_download_time(ftp_session_t* session, double dltime) {
  if (!session) {
    return FTPSYSERR;
  }

  session->dltime = dltime;

  return FTPOK;
}

/* Set session proxy */
uerr_t ftp_session_set_proxy(ftp_session_t* session, struct url* proxy) {
  if (!session) {
    return FTPSYSERR;
  }

  session->proxy = proxy;

  return FTPOK;
}

/* Check if session is connected */
bool ftp_session_is_connected(ftp_session_t* session) {
  return session && session->csock != -1;
}

/* Check if session has data connection */
bool ftp_session_has_data_connection(ftp_session_t* session) {
  return session && session->dtsock != -1;
}

/* Check if session is in passive mode */
bool ftp_session_is_passive_mode(ftp_session_t* session) {
  return session && session->local_sock == -1;
}

/* Check if session needs login */
bool ftp_session_needs_login(ftp_session_t* session) {
  return session && !ftp_session_is_connected(session);
}

/* Check if session needs directory change */
bool ftp_session_needs_directory_change(ftp_session_t* session) {
  return session && !ftp_session_has_status(session, DONE_CWD);
}

/* Close session control connection */
uerr_t ftp_session_close_control(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  if (session->csock != -1) {
    fd_close(session->csock);
    session->csock = -1;
  }

  return FTPOK;
}

/* Close session data connection */
uerr_t ftp_session_close_data(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  if (session->dtsock != -1) {
    fd_close(session->dtsock);
    session->dtsock = -1;
  }

  return FTPOK;
}

/* Close session local socket */
uerr_t ftp_session_close_local(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  if (session->local_sock != -1) {
    fd_close(session->local_sock);
    session->local_sock = -1;
  }

  return FTPOK;
}

/* Close all session connections */
uerr_t ftp_session_close_all(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  ftp_session_close_control(session);
  ftp_session_close_data(session);
  ftp_session_close_local(session);

  return FTPOK;
}

/* Reset session state */
uerr_t ftp_session_reset(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  ftp_session_close_all(session);
  xfree(session->id);
  xfree(session->target);
  session->id = NULL;
  session->target = NULL;
  session->proxy = NULL;
  session->rs = ST_UNIX;
  session->rsu = UST_OTHER;
  session->st = 0;
  session->cmd = 0;
  session->dltime = 0.0;

  return FTPOK;
}

/* Cleanup session */
uerr_t ftp_session_cleanup(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  ftp_session_close_all(session);
  xfree(session->id);
  xfree(session->target);
  session->id = NULL;
  session->target = NULL;
  session->proxy = NULL;

  return FTPOK;
}

/* Print session information for debugging */
uerr_t ftp_session_print_debug(ftp_session_t* session) {
  if (!session) {
    return FTPSYSERR;
  }

  DEBUGP(("FTP Session Debug Info:\n"));
  DEBUGP(("  Control socket: %d\n", session->csock));
  DEBUGP(("  Data socket: %d\n", session->dtsock));
  DEBUGP(("  Local socket: %d\n", session->local_sock));
  DEBUGP(("  Server type: %d\n", session->rs));
  DEBUGP(("  Unix type: %d\n", session->rsu));
  DEBUGP(("  Initial directory: %s\n", session->id ? session->id : "(null)"));
  DEBUGP(("  Target: %s\n", session->target ? session->target : "(null)"));
  DEBUGP(("  Status flags: 0x%x\n", session->st));
  DEBUGP(("  Command flags: 0x%x\n", session->cmd));
  DEBUGP(("  Download time: %.3f\n", session->dltime));

  return FTPOK;
}