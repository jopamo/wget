/* Minimal base32 encode/decode helpers
 * src/base32.h
 *
 * RFC 4648 alphabet with '=' padding, tuned for Wget compatibility
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compute encoded length (excluding terminating NUL) for a binary blob
 * Callers should allocate BASE32_LENGTH(inlen) + 1 bytes for the output buffer
 */
#define BASE32_LENGTH(inlen) ((((size_t)(inlen) + 4u) / 5u) * 8u)

/* Encode in[0..inlen) into base32
 * The output buffer must have size at least BASE32_LENGTH(inlen) + 1
 * The resulting string is always NUL-terminated when outlen > 0
 */
void base32_encode(const char* in, size_t inlen, char* out, size_t outlen);

/* Decode a base32 string into a newly allocated buffer
 *
 * On success:
 *   - returns true
 *   - *out points to a malloc'd buffer of size *outlen bytes
 *
 * On allocation failure:
 *   - returns true
 *   - *out is set to NULL
 *   - if outlen is non-NULL, *outlen carries the requested size
 *   - errno is set to ENOMEM by the implementation
 *
 * On parse error (invalid alphabet or padding):
 *   - returns false
 *   - *out is set to NULL
 *   - if outlen is non-NULL, *outlen is set to 0
 */
bool base32_decode_alloc(const char* in, size_t inlen, char** out, size_t* outlen);

#ifdef __cplusplus
}
#endif
