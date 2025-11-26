/* HTTP proxy management
 * src/http-proxy.c
 */

#include "wget.h"
#include "http-proxy.h"
#include "http-response.h"
#include "http-auth.h"
#include "http.h"
#include "utils.h"
#include "xalloc.h"
#include "log.h"
#include "connect.h"
#include "c-strcase.h"
#include "gettext.h"

#include <time.h>

void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth) {
  char *proxy_user, *proxy_passwd;

  /* When a proxy is used, credentials go to the proxy rather than the origin
     server. HTTPS targets are the exception: CONNECT handles proxy auth. */

  /* Preference order:
     - explicit --proxy-user/--proxy-password
     - credentials embedded in the proxy URL
     - explicit options win over URL-embedded credentials */

  if (opt.proxy_user && opt.proxy_passwd) {
    proxy_user = opt.proxy_user;
    proxy_passwd = opt.proxy_passwd;
  }
  else {
    proxy_user = proxy ? proxy->user : NULL;
    proxy_passwd = proxy ? proxy->passwd : NULL;
  }

  /* RFC 2617 discusses origin authentication schemes but is vague about
     proxy auth schemes; we keep this simple and send Basic here */

  if (proxy_user && proxy_passwd) {
    if (*proxyauth) {
      xfree(*proxyauth);
      *proxyauth = NULL;
    }
    *proxyauth = basic_authentication_encode(proxy_user, proxy_passwd);
  }

  /* For HTTPS, proxy auth is handled during CONNECT */
  if (u->scheme != SCHEME_HTTPS && proxyauth && *proxyauth) {
    request_set_header(req, "Proxy-Authorization", *proxyauth, rel_value);
    /* Proxy-Authorization is not kept across requests by default */
    /* request_set_header(req, "Proxy-Authorization", NULL, rel_none); */
  }
}

uerr_t establish_proxy_tunnel(const struct url* u, int sock, char** proxyauth) {
#ifdef HAVE_SSL
  int write_error;
  char* head;
  char* message = NULL;
  int statcode;
  struct response* resp;

  /* For HTTPS via an HTTP proxy, use CONNECT host:port to establish a tunnel */
  struct request* connreq = request_new("CONNECT", aprintf("%s:%d", u->host, u->port));
  request_set_user_agent(connreq);

  if (proxyauth && *proxyauth) {
    request_set_header(connreq, "Proxy-Authorization", *proxyauth, rel_value);
    /* Credentials have been folded into this CONNECT request; avoid
       reusing them for the subsequent origin request */
    *proxyauth = NULL;
  }

  request_set_header(connreq, "Host", aprintf("%s:%d", u->host, u->port), rel_value);

  write_error = request_send(connreq, sock, NULL);
  request_free(&connreq);
  if (write_error < 0) {
    /* caller is responsible for closing sock */
    return WRITEFAILED;
  }

  head = read_http_response_head(sock);
  if (!head) {
    logprintf(LOG_VERBOSE, _("Failed reading proxy response: %s\n"), fd_errstr(sock));
    return HERR;
  }

  if (!*head) {
    xfree(head);
    return HERR;
  }

  DEBUGP(("proxy responded with: [%s]\n", head));

  resp = resp_new(head);
  statcode = resp_status(resp, &message);
  if (statcode < 0) {
    char* tms = datetime_str(time(NULL));
    logprintf(LOG_VERBOSE, "%d\n", statcode);
    logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, statcode, quotearg_style(escape_quoting_style, _("Malformed status line")));
    xfree(tms);
    xfree(head);
    resp_free(&resp);
    xfree(message);
    return HERR;
  }

  resp_free(&resp);
  xfree(head);

  if (statcode != 200) {
    logprintf(LOG_NOTQUIET, _("Proxy tunneling failed: %s"), message ? quotearg_style(escape_quoting_style, message) : "?");
    xfree(message);
    return CONSSLERR;
  }

  xfree(message);
  return RETROK;
#else
  /* Without SSL support, there is no CONNECT-based proxy tunneling logic.
     Callers should have feature-gated this path already. */
  (void)u;
  (void)sock;
  (void)proxyauth;
  return RETROK;
#endif
}
