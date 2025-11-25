/* FTP Data Connection Management Implementation
 * src/ftp-data.c
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

/* Initialize data connection structure */
uerr_t ftp_data_init_connection(ftp_data_conn_t* data_conn) {
  if (!data_conn) {
    return FTPSYSERR;
  }

  data_conn->sock = -1;
  data_conn->mode = DATA_MODE_PASSIVE;
  data_conn->port = 0;
  data_conn->local_sock = -1;
  data_conn->secure = false;

  return FTPOK;
}

/* Setup passive data connection */
uerr_t ftp_data_setup_passive(int csock, ftp_data_conn_t* data_conn) {
  uerr_t err;

  if (!data_conn) {
    return FTPSYSERR;
  }

  err = ftp_do_pasv(csock, &data_conn->addr, &data_conn->port);
  if (err != FTPOK) {
    return err;
  }

  data_conn->mode = DATA_MODE_PASSIVE;
  return FTPOK;
}

/* Setup active data connection */
uerr_t ftp_data_setup_active(int csock, ftp_data_conn_t* data_conn) {
  uerr_t err;

  if (!data_conn) {
    return FTPSYSERR;
  }

  err = ftp_do_port(csock, &data_conn->local_sock);
  if (err != FTPOK) {
    return err;
  }

  data_conn->mode = DATA_MODE_ACTIVE;
  return FTPOK;
}

/* Connect data connection */
uerr_t ftp_data_connect(ftp_data_conn_t* data_conn) {
  if (!data_conn) {
    return FTPSYSERR;
  }

  if (data_conn->mode == DATA_MODE_PASSIVE) {
    data_conn->sock = connect_to_ip(&data_conn->addr, data_conn->port, NULL);
    if (data_conn->sock < 0) {
      return CONERROR;
    }
  }
  else if (data_conn->mode == DATA_MODE_ACTIVE) {
    data_conn->sock = accept_connection(data_conn->local_sock);
    if (data_conn->sock < 0) {
      return CONERROR;
    }
  }
  else {
    return FTPSYSERR;
  }

  return FTPOK;
}

/* Accept data connection (for active mode) */
uerr_t ftp_data_accept(ftp_data_conn_t* data_conn) {
  if (!data_conn || data_conn->mode != DATA_MODE_ACTIVE) {
    return FTPSYSERR;
  }

  data_conn->sock = accept_connection(data_conn->local_sock);
  if (data_conn->sock < 0) {
    return CONERROR;
  }

  return FTPOK;
}

/* Secure data connection with SSL/TLS */
uerr_t ftp_data_secure_connection(ftp_data_conn_t* data_conn, struct url* u, int csock) {
#ifdef HAVE_SSL
  if (!data_conn || !u) {
    return FTPSYSERR;
  }

  if (u->scheme == SCHEME_FTPS && data_conn->secure) {
    /* We should try to restore the existing SSL session in the data connection
     * and fall back to establishing a new session if the server doesn't want to restore it.
     */
    if (!opt.ftps_resume_ssl || !ssl_connect_wget(data_conn->sock, u->host, &csock)) {
      if (opt.ftps_resume_ssl)
        logputs(LOG_NOTQUIET, "Server does not want to resume the SSL session. Trying with a new one.\n");
      if (!ssl_connect_wget(data_conn->sock, u->host, NULL)) {
        return CONERROR;
      }
    }
    else {
      logputs(LOG_NOTQUIET, "Resuming SSL session in data connection.\n");
    }

    if (!ssl_check_certificate(data_conn->sock, u->host)) {
      return CONERROR;
    }
  }
#endif

  return FTPOK;
}

/* Cleanup data connection */
uerr_t ftp_data_cleanup(ftp_data_conn_t* data_conn) {
  if (!data_conn) {
    return FTPSYSERR;
  }

  if (data_conn->sock != -1) {
    fd_close(data_conn->sock);
    data_conn->sock = -1;
  }

  if (data_conn->local_sock != -1) {
    fd_close(data_conn->local_sock);
    data_conn->local_sock = -1;
  }

  return FTPOK;
}

/* Transfer file over data connection */
uerr_t ftp_data_transfer_file(ftp_data_conn_t* data_conn, const char* local_file, wgint expected_bytes, wgint restval, wgint* qtyread, double* dltime, FILE* warc_tmp) {
  FILE* fp = NULL;
  int res;
  int flags = 0;
  wgint rd_size = 0;

  if (!data_conn || !local_file || !qtyread || !dltime) {
    return FTPSYSERR;
  }

  /* Open the local file */
  if (restval > 0) {
    fp = fopen(local_file, "ab");
  }
  else {
    fp = fopen_excl(local_file, true);
    if (!fp && errno == EEXIST) {
      return FOPEN_EXCL_ERR;
    }
  }

  if (!fp) {
    return FOPENERR;
  }

  /* Transfer the data */
  res = fd_read_body(local_file, data_conn->sock, fp, expected_bytes ? expected_bytes - restval : 0, restval, &rd_size, qtyread, dltime, flags, warc_tmp);

  fclose(fp);

  if (res == -2 || (warc_tmp != NULL && res == -3)) {
    return FWRITEERR;
  }
  else if (res == -1) {
    return FTPRETRINT;
  }

  return FTPOK;
}

/* Transfer directory listing over data connection */
uerr_t ftp_data_transfer_listing(ftp_data_conn_t* data_conn, const char* local_file, wgint* qtyread, double* dltime) {
  FILE* fp = NULL;
  int res;
  int flags = 0;
  wgint rd_size = 0;

  if (!data_conn || !local_file || !qtyread || !dltime) {
    return FTPSYSERR;
  }

  /* Open the listing file */
  fp = fopen_excl(local_file, false);
  if (!fp && errno == EEXIST) {
    return FOPEN_EXCL_ERR;
  }
  if (!fp) {
    return FOPENERR;
  }

  /* Transfer the listing data */
  res = fd_read_body(local_file, data_conn->sock, fp, 0, 0, &rd_size, qtyread, dltime, flags, NULL);

  fclose(fp);

  if (res == -2) {
    return FWRITEERR;
  }
  else if (res == -1) {
    return FTPRETRINT;
  }

  return FTPOK;
}

/* Check if data connection is connected */
bool ftp_data_is_connected(const ftp_data_conn_t* data_conn) {
  return data_conn && data_conn->sock != -1;
}

/* Close data connection */
uerr_t ftp_data_close(ftp_data_conn_t* data_conn) {
  if (!data_conn) {
    return FTPSYSERR;
  }

  if (data_conn->sock != -1) {
    fd_close(data_conn->sock);
    data_conn->sock = -1;
  }

  return FTPOK;
}