/* Minimal base32 encode/decode helpers derived from RFC 4648.
   Copyright (C) 1999-2025 Free Software Foundation,
   Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this file.  If not, see <https://www.gnu.org/licenses/>.  */

#pragma once

#include <stddef.h>
#include <stdbool.h>

#define BASE32_LENGTH(inlen) ((((inlen) + 4) / 5) * 8)

void base32_encode(const char* in, size_t inlen, char* out, size_t outlen);
bool base32_decode_alloc(const char* in, size_t inlen, char** out, size_t* outlen);
