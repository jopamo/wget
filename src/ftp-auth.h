/* FTP Authentication and Login Management
 * src/ftp-auth.h
 */

#ifndef FTP_AUTH_H
#define FTP_AUTH_H

#include "wget.h"
#include "url.h"
#include "ftp-types.h"

/* Authentication context structure */
typedef struct {
  char* user;                  /* username for login */
  char* passwd;                /* password for login */
  bool using_control_security; /* whether control connection is secure */
  bool using_data_security;    /* whether data connection is secure */
  struct url* proxy;           /* proxy URL */
  bool logged_in;              /* whether successfully logged in */
} ftp_auth_ctx_t;

/* Authentication functions */
uerr_t ftp_auth_login(ftp_session_t* session, struct url* u);
uerr_t ftp_auth_get_credentials(struct url* u, const char** user, const char** passwd);
uerr_t ftp_auth_validate_credentials(const char* user, const char* passwd);

/* Security and encryption functions */
uerr_t ftp_auth_secure_control(ftp_session_t* session, struct url* u);
uerr_t ftp_auth_secure_data(ftp_session_t* session, struct url* u);
uerr_t ftp_auth_init_ssl(ftp_session_t* session, struct url* u);

/* Proxy authentication */
uerr_t ftp_auth_proxy_login(ftp_session_t* session, struct url* u, struct url* proxy);
char* ftp_auth_build_proxy_username(const char* user, const char* host);

/* S/Key authentication support */
uerr_t ftp_auth_skey_response(ftp_session_t* session, const char* challenge);
char* ftp_auth_skey_compute_response(const char* challenge, const char* passwd);

/* Authentication context management */
uerr_t ftp_auth_init_context(ftp_auth_ctx_t* ctx, struct url* u);
uerr_t ftp_auth_cleanup_context(ftp_auth_ctx_t* ctx);

/* Authentication status and validation */
bool ftp_auth_is_logged_in(const ftp_session_t* session);
uerr_t ftp_auth_validate_session(const ftp_session_t* session);

/* Security protocol functions */
uerr_t ftp_auth_send_pbsz(ftp_session_t* session, int pbsz);
uerr_t ftp_auth_send_prot(ftp_session_t* session, enum prot_level prot);

#endif /* FTP_AUTH_H */