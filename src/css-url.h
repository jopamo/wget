/* Declarations for css-url.c
 * src/css-url.h
 */

#ifndef CSS_URL_H
#define CSS_URL_H

#ifdef __cplusplus
extern "C" {
#endif

struct map_context; /* parsing state shared with HTML URL collector */
struct urlpos;      /* link position descriptor from convert/html-url */

/* Scan a CSS snippet for @import and url() references and append them
 * to the map_context URL list
 *
 * CTX       parser context (must remain valid for the lifetime of urlpos list)
 * OFFSET    starting offset into CTX->text
 * BUF_LEN   number of bytes from CTX->text + OFFSET to scan
 */
void get_urls_css(struct map_context* ctx, int offset, int buf_len);

/* Collect all URLs from a CSS file on disk
 *
 * FILE      path to the CSS file on disk
 * URL       base URL used to resolve relative links
 *
 * Returns a linked list of urlpos nodes or NULL on error
 * The caller owns and must free the returned list with free_urlpos()
 */
struct urlpos* get_urls_css_file(const char* file, const char* url);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CSS_URL_H */
