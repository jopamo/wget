#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

#include "wget.h"
#include "url.h"
#include "http-request.h"

void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth);
uerr_t establish_proxy_tunnel(const struct url* u, int sock, char** proxyauth);

#endif /* HTTP_PROXY_H */
