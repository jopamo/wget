#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include <stdbool.h>
#include "wget.h"
#include "http-request.h"

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

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

char* basic_authentication_encode(const char* user, const char* passwd);
bool known_authentication_scheme_p(const char* hdrbeg, const char* hdrend);
bool maybe_send_basic_creds(const char* hostname, const char* user, const char* passwd, struct request* req);
void register_basic_auth_host(const char* hostname);
void http_auth_cleanup(void);

#endif /* HTTP_AUTH_H */
