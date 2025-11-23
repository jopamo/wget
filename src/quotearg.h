/* Simplified quotearg interface compatible with gnulib's headers.
 * src/quotearg.h
 */

#ifndef WGET_QUOTEARG_H
#define WGET_QUOTEARG_H

enum quoting_style { literal_quoting_style = 0, escape_quoting_style = 1 };

const char* quotearg_style(enum quoting_style style, const char* arg);
const char* quotearg_n_style(int n, enum quoting_style style, const char* arg);
void quotearg_free(void);

#endif /* WGET_QUOTEARG_H */
