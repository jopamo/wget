/* Simplified quoting helpers replacing gnulib's quote module.
 * src/quote.h
 */

#ifndef WGET_QUOTE_H
#define WGET_QUOTE_H

const char* quote(const char* arg);
const char* quote_n(int n, const char* arg);

#endif /* WGET_QUOTE_H */
