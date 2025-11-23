/* Minimal base32 helpers compatible with Wget's historical gnulib usage
 * src/base32.c
 *
 * Based on RFC 4648 reference implementations
 */

#include "config.h"

#include "base32.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

static unsigned char to_uchar(char ch) {
  return (unsigned char)ch;
}

void base32_encode(const char* in, size_t inlen, char* out, size_t outlen) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  size_t outpos = 0;
  size_t i = 0;

  if (outlen == 0)
    return;

  while (i < inlen && outpos + 8 < outlen) {
    unsigned char b[5] = {0, 0, 0, 0, 0};
    size_t chunk_len = inlen - i;

    if (chunk_len > 5)
      chunk_len = 5;

    for (size_t j = 0; j < chunk_len; ++j)
      b[j] = to_uchar(in[i + j]);

    unsigned int x0 = b[0];
    unsigned int x1 = b[1];
    unsigned int x2 = b[2];
    unsigned int x3 = b[3];
    unsigned int x4 = b[4];

    char ob[8];

    ob[0] = alphabet[(x0 >> 3) & 0x1f];
    ob[1] = alphabet[((x0 << 2) | (x1 >> 6)) & 0x1f];
    ob[2] = (chunk_len > 1) ? alphabet[((x1 >> 1) & 0x1f)] : '=';
    ob[3] = (chunk_len > 1) ? alphabet[((x1 << 4) | (x2 >> 4)) & 0x1f] : '=';
    ob[4] = (chunk_len > 2) ? alphabet[((x2 << 1) | (x3 >> 7)) & 0x1f] : '=';
    ob[5] = (chunk_len > 3) ? alphabet[((x3 >> 2) & 0x1f)] : '=';
    ob[6] = (chunk_len > 3) ? alphabet[((x3 << 3) | (x4 >> 5)) & 0x1f] : '=';
    ob[7] = (chunk_len > 4) ? alphabet[(x4 & 0x1f)] : '=';

    for (size_t k = 0; k < 8 && outpos + 1 < outlen; ++k)
      out[outpos++] = ob[k];

    i += chunk_len;
  }

  out[outpos] = '\0';
}

static int base32_decode_value(unsigned char ch) {
  if (ch >= 'A' && ch <= 'Z')
    return ch - 'A';
  if (ch >= 'a' && ch <= 'z')
    return ch - 'a';
  if (ch >= '2' && ch <= '7')
    return 26 + (ch - '2');
  return -1;
}

static bool base32_decode_block(const unsigned char block[8], char* buffer, size_t* written, size_t max_out) {
#define APPEND_BYTE(value)                     \
  do {                                         \
    if (*written >= max_out)                   \
      return false;                            \
    buffer[*written] = (char)((value) & 0xff); \
    (*written)++;                              \
  } while (0)

  unsigned char values[8] = {0};
  int first_pad = -1;

  for (int i = 0; i < 8; ++i) {
    unsigned char ch = block[i];

    if (ch == '=') {
      if (first_pad < 0)
        first_pad = i;
    }
    else {
      if (first_pad >= 0)
        return false;

      int v = base32_decode_value(ch);
      if (v < 0)
        return false;

      values[i] = (unsigned char)v;
    }
  }

  size_t pad = (first_pad < 0) ? 0u : (size_t)(8 - first_pad);

  switch (pad) {
    case 0:
      APPEND_BYTE((values[0] << 3) | (values[1] >> 2));
      APPEND_BYTE((values[1] << 6) | (values[2] << 1) | (values[3] >> 4));
      APPEND_BYTE((values[3] << 4) | (values[4] >> 1));
      APPEND_BYTE((values[4] << 7) | (values[5] << 2) | (values[6] >> 3));
      APPEND_BYTE((values[6] << 5) | values[7]);
      break;
    case 1:
      if (first_pad != 7)
        return false;
      APPEND_BYTE((values[0] << 3) | (values[1] >> 2));
      APPEND_BYTE((values[1] << 6) | (values[2] << 1) | (values[3] >> 4));
      APPEND_BYTE((values[3] << 4) | (values[4] >> 1));
      APPEND_BYTE((values[4] << 7) | (values[5] << 2) | (values[6] >> 3));
      break;
    case 3:
      if (first_pad != 5)
        return false;
      APPEND_BYTE((values[0] << 3) | (values[1] >> 2));
      APPEND_BYTE((values[1] << 6) | (values[2] << 1) | (values[3] >> 4));
      APPEND_BYTE((values[3] << 4) | (values[4] >> 1));
      break;
    case 4:
      if (first_pad != 4)
        return false;
      APPEND_BYTE((values[0] << 3) | (values[1] >> 2));
      APPEND_BYTE((values[1] << 6) | (values[2] << 1) | (values[3] >> 4));
      break;
    case 6:
      if (first_pad != 2)
        return false;
      APPEND_BYTE((values[0] << 3) | (values[1] >> 2));
      break;
    default:
      return false;
  }

#undef APPEND_BYTE
  return true;
}

bool base32_decode_alloc(const char* in, size_t inlen, char** out, size_t* outlen) {
  size_t max_out;
  size_t written = 0;
  unsigned char block[8];
  size_t block_len = 0;
  char* buffer;

  if (out == NULL)
    return false;

  *out = NULL;
  if (outlen)
    *outlen = 0;

  max_out = 5 * ((inlen >> 3) + 1);
  if (max_out == 0)
    max_out = 1;

  buffer = malloc(max_out);
  if (buffer == NULL) {
    if (outlen)
      *outlen = max_out;
    errno = ENOMEM;
    return true;
  }

  for (size_t i = 0; i < inlen; ++i) {
    unsigned char ch = to_uchar(in[i]);

    if (isspace(ch))
      continue;

    block[block_len++] = ch;

    if (block_len == 8) {
      if (!base32_decode_block(block, buffer, &written, max_out)) {
        free(buffer);
        *out = NULL;
        if (outlen)
          *outlen = 0;
        return false;
      }
      block_len = 0;
    }
  }

  if (block_len != 0) {
    free(buffer);
    *out = NULL;
    if (outlen)
      *outlen = 0;
    return false;
  }

  *out = buffer;
  if (outlen)
    *outlen = written;

  return true;
}
