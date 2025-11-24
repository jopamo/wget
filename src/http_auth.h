/* HTTP authentication helpers.
 * src/http_auth.h
 */

#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include "wget.h"

struct request;
struct ntlmdata;

bool http_auth_maybe_send_basic_creds(const char* hostname, const char* user, const char* passwd, struct request* req);
void http_auth_register_basic_challenge(const char* hostname);
char* http_auth_basic_encode(const char* user, const char* passwd);
bool http_auth_known_scheme(const char* hdrbeg, const char* hdrend);
char* http_auth_create_authorization_line(const char* challenge,
                                          const char* user,
                                          const char* passwd,
                                          const char* method,
                                          const char* path,
                                          struct ntlmdata* ntlm_state,
                                          bool* finished,
                                          uerr_t* auth_err);
void http_auth_cleanup(void);

#endif /* HTTP_AUTH_H */
