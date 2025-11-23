/* Minimal SHA1 interface
 * src/sha1.h
 */

#ifndef WGET_SHA1_H
#define WGET_SHA1_H

#include <stddef.h>
#include <stdio.h>

#define SHA1_DIGEST_SIZE 20

#include <openssl/evp.h>
typedef struct sha1_ctx {
  EVP_MD_CTX* impl;
} sha1_ctx;

void sha1_init_ctx(struct sha1_ctx* ctx);
void sha1_process_bytes(const void* buffer, size_t len, struct sha1_ctx* ctx);
void sha1_finish_ctx(struct sha1_ctx* ctx, void* resbuf);
int sha1_stream(FILE* stream, void* resblock);

#endif /* WGET_SHA1_H */
