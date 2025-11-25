/* FTP Session Management
 * src/ftp-session.h
 */

#ifndef FTP_SESSION_H
#define FTP_SESSION_H

#include "wget.h"
#include "url.h"
#include "ftp-types.h"

/* FTP session context structure */
typedef struct {
  int csock;         /* control connection socket */
  int dtsock;        /* data connection socket */
  int local_sock;    /* local socket for active mode */
  enum stype rs;     /* remote system type */
  enum ustype rsu;   /* remote system type details */
  char* id;          /* initial directory */
  char* target;      /* target file name */
  struct url* proxy; /* proxy URL */
  int st;            /* session status flags */
  int cmd;           /* current command flags */
  double dltime;     /* download time */
} ftp_session_t;

/* Session status flags */
#define SESSION_ACTIVE 0x0001
#define SESSION_LOGGED_IN 0x0002
#define SESSION_SECURE_CONTROL 0x0004
#define SESSION_SECURE_DATA 0x0008
#define SESSION_CWD_DONE 0x0010

/* Session management functions */
uerr_t ftp_session_init(ftp_session_t* session, struct url* proxy);
uerr_t ftp_session_connect(ftp_session_t* session, struct url* u);
uerr_t ftp_session_login(ftp_session_t* session, struct url* u);
uerr_t ftp_session_disconnect(ftp_session_t* session);
uerr_t ftp_session_cleanup(ftp_session_t* session);

/* Session state management */
uerr_t ftp_session_set_cwd(ftp_session_t* session, const char* dir);
uerr_t ftp_session_get_pwd(ftp_session_t* session, char** pwd);
uerr_t ftp_session_set_type(ftp_session_t* session, char type_char);

/* High-level FTP operations */
uerr_t ftp_session_retrieve_file(ftp_session_t* session, struct url* u, wgint* qtyread, wgint restval, FILE* warc_tmp);
uerr_t ftp_session_get_listing(ftp_session_t* session, struct url* u, struct fileinfo** f);

#endif /* FTP_SESSION_H */