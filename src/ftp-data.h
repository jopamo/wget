/* FTP Data Connection Management
 * src/ftp-data.h
 */

#ifndef FTP_DATA_H
#define FTP_DATA_H

#include "wget.h"
#include "url.h"
#include "host.h"

/* Data connection mode enumeration */
typedef enum { DATA_MODE_PASSIVE, DATA_MODE_ACTIVE } ftp_data_mode_t;

/* Data connection structure */
typedef struct {
  int sock;             /* data connection socket */
  ftp_data_mode_t mode; /* connection mode (passive/active) */
  ip_address addr;      /* remote address for passive mode */
  int port;             /* remote port for passive mode */
  int local_sock;       /* local socket for active mode */
  bool secure;          /* whether data connection is secure */
} ftp_data_conn_t;

/* Data connection setup functions */
uerr_t ftp_data_setup_passive(int csock, ftp_data_conn_t* data_conn);
uerr_t ftp_data_setup_active(int csock, ftp_data_conn_t* data_conn);
uerr_t ftp_data_connect(ftp_data_conn_t* data_conn);
uerr_t ftp_data_accept(ftp_data_conn_t* data_conn);

/* Data connection security functions */
uerr_t ftp_data_secure_connection(ftp_data_conn_t* data_conn, struct url* u, int csock);

/* Data connection cleanup */
uerr_t ftp_data_cleanup(ftp_data_conn_t* data_conn);

/* Data transfer functions */
uerr_t ftp_data_transfer_file(ftp_data_conn_t* data_conn, const char* local_file, wgint expected_bytes, wgint restval, wgint* qtyread, double* dltime, FILE* warc_tmp);
uerr_t ftp_data_transfer_listing(ftp_data_conn_t* data_conn, const char* local_file, wgint* qtyread, double* dltime);

/* Data connection utility functions */
bool ftp_data_is_connected(const ftp_data_conn_t* data_conn);
uerr_t ftp_data_close(ftp_data_conn_t* data_conn);

#endif /* FTP_DATA_H */