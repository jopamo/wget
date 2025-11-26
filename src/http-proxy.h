/* HTTP proxy configuration and tunnel support
 * src/http-proxy.h
 */
#ifndef HTTP_PROXY_H
#define HTTP_PROXY_H

#include "wget.h"
#include "url.h"
#include "http-request.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize proxy-related state for a request
 *
 * u         target origin URL
 * req       HTTP request to annotate with proxy headers
 * proxy     parsed proxy URL to use for this request
 * proxyauth pointer to cached proxy Authorization header value
 */
void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth);

/* Establish a CONNECT tunnel through an HTTP proxy
 *
 * u         target origin URL (host:port to tunnel to)
 * sock      connected socket to the proxy
 * proxyauth pointer to cached proxy Authorization header value
 *
 * Returns a uerr_t status code describing tunnel setup result
 */
uerr_t establish_proxy_tunnel(const struct url* u, int sock, char** proxyauth);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_PROXY_H */
