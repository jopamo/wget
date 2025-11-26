/* HTTP proxy management.
   Separated from http.c. */

#include "wget.h"
#include "http-proxy.h"
#include "http-response.h"
#include "http-auth.h"
#include "http.h" /* for fd_read_hunk, fd_write, etc via utils */
#include "utils.h"
#include "xalloc.h"
#include "log.h"
#include "connect.h"
#include "c-strcase.h"
#include "gettext.h"
#include "time.h"

void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth) {
  char *proxy_user, *proxy_passwd;

  /* When the proxy is used, we send the user credentials to the proxy
     server.  However, if we are using the proxy for retrieval of an
     SSL URL, we don't send the credentials, because the proxy
     authentication is handled by the CONNECT method.  */

  /* A bit of explanation:
     - If the user specified --proxy-user and --proxy-password, we
       use those.
     - If the proxy URL contained a username and password, we use
       those.
     - If both are specified, --proxy-user wins.  */

  if (opt.proxy_user && opt.proxy_passwd) {
    proxy_user = opt.proxy_user;
    proxy_passwd = opt.proxy_passwd;
  }
  else {
    proxy_user = proxy->user;
    proxy_passwd = proxy->passwd;
  }

  /* #### This does not appear right.  Can't the proxy request,
     strictly speaking, use a different auth scheme?  RFC 2617 says
     that "A client SHOULD assume that all paths at a single
     proxy/resource server are protected by the same [authentication]
     scheme."  It doesn't say anything about the proxy authentication
     scheme.  */

  if (proxy_user && proxy_passwd)
    *proxyauth = basic_authentication_encode(proxy_user, proxy_passwd);

  /* Proxy authorization over SSL is handled below. */
  if (u->scheme != SCHEME_HTTPS && *proxyauth) {
    request_set_header(req, "Proxy-Authorization", *proxyauth, rel_value);
    /* The Proxy-Authorization header is special in that it is not
       kept in the request by default.  */
    // request_set_header (req, "Proxy-Authorization", NULL, rel_none);
  }
}

extern char* read_http_response_head(int fd); /* defined in http.c, needed here */

uerr_t establish_proxy_tunnel(const struct url* u, int sock, char** proxyauth) {
#ifdef HAVE_SSL
  int write_error;
  char* head;
  char* message;
  int statcode;
  struct response* resp;

  /* When requesting SSL URLs through proxies, use the
     CONNECT method to request passthrough.  */
  struct request* connreq = request_new("CONNECT", aprintf("%s:%d", u->host, u->port));
  request_set_user_agent(connreq);
  if (proxyauth && *proxyauth) {
    request_set_header(connreq, "Proxy-Authorization", *proxyauth, rel_value);
    /* Now that PROXYAUTH is part of the CONNECT request,
       zero it out so we don't send proxy authorization with
       the regular request below.  */
    *proxyauth = NULL;
  }
  request_set_header(connreq, "Host", aprintf("%s:%d", u->host, u->port), rel_value);

  write_error = request_send(connreq, sock, 0);
  request_free(&connreq);
  if (write_error < 0) {
    // CLOSE_INVALIDATE(sock); // Caller handles closure
    return WRITEFAILED;
  }

  head = read_http_response_head(sock);
  if (!head) {
    logprintf(LOG_VERBOSE, _("Failed reading proxy response: %s\n"), fd_errstr(sock));
    // CLOSE_INVALIDATE(sock); // Caller handles closure
    return HERR;
  }
  message = NULL;
  if (!*head) {
    xfree(head);
    return HERR;  // Was goto failed_tunnel
  }
  DEBUGP(("proxy responded with: [%s]\n", head));

  resp = resp_new(head);
  statcode = resp_status(resp, &message);
  if (statcode < 0) {
    char* tms = datetime_str(time(NULL));
    logprintf(LOG_VERBOSE, "%d\n", statcode);
    logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, statcode, quotearg_style(escape_quoting_style, _("Malformed status line")));
    xfree(head);
    resp_free(&resp);
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
  return RETROK;
#endif
}
