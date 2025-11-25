/* FTP Command Processing Implementation
 * src/ftp-commands.c
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

/*
 * This function sets up a passive data connection with the FTP server.
 * It is merely a wrapper around ftp_epsv, ftp_lpsv and ftp_pasv.
 */
uerr_t ftp_do_pasv(int csock, ip_address* addr, int* port) {
  uerr_t err;

  /* We need to determine the address family and need to call
     getpeername, so while we're at it, store the address to ADDR.
     ftp_pasv and ftp_lpsv can simply override it.  */
  if (!socket_ip_address(csock, addr, ENDPOINT_PEER))
    abort();

  /* If our control connection is over IPv6, then we first try EPSV and then
   * LPSV if the former is not supported. If the control connection is over
   * IPv4, we simply issue the good old PASV request. */
  switch (addr->family) {
    case AF_INET:
      if (!opt.server_response)
        logputs(LOG_VERBOSE, "==> PASV ... ");
      err = ftp_pasv(csock, addr, port);
      break;
    case AF_INET6:
      if (!opt.server_response)
        logputs(LOG_VERBOSE, "==> EPSV ... ");
      err = ftp_epsv(csock, addr, port);

      /* If EPSV is not supported try LPSV */
      if (err == FTPNOPASV) {
        if (!opt.server_response)
          logputs(LOG_VERBOSE, "==> LPSV ... ");
        err = ftp_lpsv(csock, addr, port);
      }
      break;
    default:
      abort();
  }

  return err;
}

/*
 * This function sets up an active data connection with the FTP server.
 * It is merely a wrapper around ftp_eprt, ftp_lprt and ftp_port.
 */
uerr_t ftp_do_port(int csock, int* local_sock) {
  uerr_t err;
  ip_address cip;

  if (!socket_ip_address(csock, &cip, ENDPOINT_PEER))
    abort();

  /* If our control connection is over IPv6, then we first try EPRT and then
   * LPRT if the former is not supported. If the control connection is over
   * IPv4, we simply issue the good old PORT request. */
  switch (cip.family) {
    case AF_INET:
      if (!opt.server_response)
        logputs(LOG_VERBOSE, "==> PORT ... ");
      err = ftp_port(csock, local_sock);
      break;
    case AF_INET6:
      if (!opt.server_response)
        logputs(LOG_VERBOSE, "==> EPRT ... ");
      err = ftp_eprt(csock, local_sock);

      /* If EPRT is not supported try LPRT */
      if (err == FTPPORTERR) {
        if (!opt.server_response)
          logputs(LOG_VERBOSE, "==> LPRT ... ");
        err = ftp_lprt(csock, local_sock);
      }
      break;
    default:
      abort();
  }
  return err;
}

/* Process FTP transfer type from URL parameters */
/* Note: ftp_process_type is implemented in ftp-basic.c */

/* Execute FTP command with value */
uerr_t ftp_execute_command(int csock, const char* command, const char* value) {
  uerr_t err;

  /* Send the command */
  err = ftp_send_command(csock, command, value);
  if (err != FTPOK) {
    return err;
  }

  /* Read and process response */
  return ftp_read_response(csock, NULL);
}

/* Send FTP command to server */
uerr_t ftp_send_command(int csock, const char* command, const char* value) {
  char buf[1024];
  int len;

  if (value) {
    len = snprintf(buf, sizeof(buf), "%s %s\r\n", command, value);
  }
  else {
    len = snprintf(buf, sizeof(buf), "%s\r\n", command);
  }

  if (len >= (int)sizeof(buf)) {
    logputs(LOG_NOTQUIET, _("FTP command too long\n"));
    return WRITEFAILED;
  }

  if (fd_write(csock, buf, len, -1) != len) {
    return WRITEFAILED;
  }

  return FTPOK;
}

/* Read FTP response from server */
uerr_t ftp_read_response(int csock, char** response) {
  return ftp_response(csock, response);
}

/* Get FTP server greeting */
uerr_t ftp_command_get_greeting(int csock) {
  return ftp_greeting(csock);
}

/* Execute USER command */
uerr_t ftp_command_user(int csock, const char* username) {
  return ftp_execute_command(csock, "USER", username);
}

/* Execute PASS command */
uerr_t ftp_command_pass(int csock, const char* password) {
  return ftp_execute_command(csock, "PASS", password);
}

/* Execute SYST command */
uerr_t ftp_command_syst(int csock, enum stype* server_type, enum ustype* unix_type) {
  return ftp_syst(csock, server_type, unix_type);
}

/* Execute PWD command */
uerr_t ftp_command_pwd(int csock, char** pwd) {
  return ftp_pwd(csock, pwd);
}

/* Execute TYPE command */
uerr_t ftp_command_type(int csock, char type_char) {
  return ftp_type(csock, type_char);
}

/* Execute CWD command */
uerr_t ftp_command_cwd(int csock, const char* dir) {
  return ftp_cwd(csock, dir);
}

/* Execute REST command */
uerr_t ftp_command_rest(int csock, wgint offset) {
  return ftp_rest(csock, offset);
}

/* Execute RETR command */
uerr_t ftp_command_retr(int csock, const char* file) {
  return ftp_retr(csock, file);
}

/* Execute LIST command */
uerr_t ftp_command_list(int csock, const char* file, bool avoid_list_a, bool avoid_list, bool* list_a_used) {
  return ftp_list(csock, file, avoid_list_a, avoid_list, list_a_used);
}

/* Execute SIZE command */
uerr_t ftp_command_size(int csock, const char* file, wgint* size) {
  return ftp_size(csock, file, size);
}

/* Execute PASV command */
uerr_t ftp_command_pasv(int csock, ip_address* addr, int* port) {
  return ftp_pasv(csock, addr, port);
}

/* Execute PORT command */
uerr_t ftp_command_port(int csock, int* local_sock) {
  return ftp_port(csock, local_sock);
}

#ifdef ENABLE_IPV6
/* Execute EPSV command */
uerr_t ftp_command_epsv(int csock, ip_address* ip, int* port) {
  return ftp_epsv(csock, ip, port);
}

/* Execute EPRT command */
uerr_t ftp_command_eprt(int csock, int* local_sock) {
  return ftp_eprt(csock, local_sock);
}

/* Execute LPSV command */
uerr_t ftp_command_lpsv(int csock, ip_address* addr, int* port) {
  return ftp_lpsv(csock, addr, port);
}

/* Execute LPRT command */
uerr_t ftp_command_lprt(int csock, int* local_sock) {
  return ftp_lprt(csock, local_sock);
}
#endif

#ifdef HAVE_SSL
/* Execute AUTH command */
uerr_t ftp_command_auth(int csock, enum url_scheme scheme) {
  return ftp_auth(csock, scheme);
}

/* Execute PBSZ command */
uerr_t ftp_command_pbsz(int csock, int pbsz) {
  return ftp_pbsz(csock, pbsz);
}

/* Execute PROT command */
uerr_t ftp_command_prot(int csock, enum prot_level prot) {
  return ftp_prot(csock, prot);
}
#endif