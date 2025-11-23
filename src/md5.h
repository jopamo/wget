/* Minimal MD5 interface wrappers
 * src/md5.h
 */

#ifndef WGET_MD5_H
#define WGET_MD5_H

#include <stddef.h>
#include <stdio.h>

#define MD5_DIGEST_SIZE 16

#include <openssl/md5.h>
typedef struct md5_ctx {
  MD5_CTX impl;
} md5_ctx;

void md5_init_ctx(struct md5_ctx* ctx);
void md5_process_bytes(const void* buffer, size_t len, struct md5_ctx* ctx);
void md5_finish_ctx(struct md5_ctx* ctx, void* resbuf);
int md5_stream(FILE* stream, void* resblock);

#endif /* WGET_MD5_H */
