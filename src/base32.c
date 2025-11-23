/* Minimal base32 helpers compatible with Wget's historical gnulib usage.
   Based on RFC 4648 reference implementations.
   Copyright (C) 1999-2025
   Free Software Foundation, Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this file.  If not, see <https://www.gnu.org/licenses/>.  */

#include "config.h"

#include "base32.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static unsigned char to_uchar(char ch) {
  return (unsigned char)ch;
}

void base32_encode(const char* in, size_t inlen, char* out, size_t outlen) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  while (inlen && outlen) {
    *out++ = alphabet[(to_uchar(in[0]) >> 3) & 0x1f];
    if (!--outlen)
      break;
    *out++ = alphabet[((to_uchar(in[0]) << 2) + (--inlen ? to_uchar(in[1]) >> 6 : 0)) & 0x1f];
    if (!--outlen)
      break;
    *out++ = (inlen ? alphabet[(to_uchar(in[1]) >> 1) & 0x1f] : '=');
    if (!--outlen)
      break;
    *out++ = (inlen ? alphabet[((to_uchar(in[1]) << 4) + (--inlen ? to_uchar(in[2]) >> 4 : 0)) & 0x1f] : '=');
    if (!--outlen)
      break;
    *out++ = (inlen ? alphabet[((to_uchar(in[2]) << 1) + (--inlen ? to_uchar(in[3]) >> 7 : 0)) & 0x1f] : '=');
    if (!--outlen)
      break;
    *out++ = (inlen ? alphabet[(to_uchar(in[3]) >> 2) & 0x1f] : '=');
    if (!--outlen)
      break;
    *out++ = (inlen ? alphabet[((to_uchar(in[3]) << 3) + (--inlen ? to_uchar(in[4]) >> 5 : 0)) & 0x1f] : '=');
    if (!--outlen)
      break;
    *out++ = inlen ? alphabet[to_uchar(in[4]) & 0x1f] : '=';
    if (!--outlen)
      break;
    if (inlen)
      inlen--;
    if (inlen)
      in += 5;
  }

  if (outlen)
    *out = '\0';
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

  size_t pad = (first_pad < 0) ? 0 : (size_t)(8 - first_pad);

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
  size_t max_out = 5 * ((inlen >> 3) + 1);
  size_t written = 0;
  unsigned char block[8];
  size_t block_len = 0;
  char* buffer;

  if (out == NULL)
    return false;

  if (max_out == 0)
    max_out = 1;

  buffer = malloc(max_out);
  if (buffer == NULL) {
    if (outlen)
      *outlen = max_out;
    *out = NULL;
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
