/* HTTP authentication support (Basic, Digest, NTLM)
 * src/http-auth.h
 */
#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include <stdbool.h>
#include "http-request.h"

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Build an Authorization header value for a single challenge line
 *
 * au        raw WWW-Authenticate or Proxy-Authenticate header value
 * user      username to authenticate with
 * passwd    password associated with user
 * method    HTTP method for this request (e.g. "GET")
 * path      request path or URI component used in the digest calculation
 * finished  set to true when no further auth round-trips are needed
 * auth_err  filled with an error code when digest parsing fails
 * ntlm      optional NTLM state when ENABLE_NTLM is enabled
 *
 * Returns a freshly allocated header value string (without "Authorization: ")
 * or NULL when the scheme is unsupported or negotiation fails
 */
char* create_authorization_line(const char* au,
                                const char* user,
                                const char* passwd,
                                const char* method,
                                const char* path,
                                bool* finished,
                                uerr_t* auth_err
#ifdef ENABLE_NTLM
                                ,
                                struct ntlmdata* ntlm
#endif
);

/* Encode "user:passwd" as a Basic auth header value without the field name
 * Caller owns the returned buffer
 */
char* basic_authentication_encode(const char* user, const char* passwd);

/* Check whether hdrbeg..hdrend names an authentication scheme we understand
 * Currently recognizes Basic, Digest, and optionally NTLM
 */
bool known_authentication_scheme_p(const char* hdrbeg, const char* hdrend);

/* Opportunistically attach Basic credentials to a request if the host
 * is known to require them or auth_without_challenge is enabled
 * Returns true if an Authorization header was added
 */
bool maybe_send_basic_creds(const char* hostname, const char* user, const char* passwd, struct request* req);

/* Remember that HOSTNAME has successfully challenged us for Basic auth
 * used so future requests can pre-send credentials
 */
void register_basic_auth_host(const char* hostname);

/* Release any global authentication state cached by this module */
void http_auth_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_AUTH_H */
