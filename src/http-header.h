/* Declarations for HTTP header utilities.
 * src/http-header.h
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.
 *
 * This file is part of GNU Wget.
 *
 * GNU Wget is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HTTP_HEADER_H
#define HTTP_HEADER_H

#include <stdbool.h>
#include <time.h>

time_t http_atotm(const char*);

typedef struct {
  /* A token consists of characters in the [b, e) range. */
  const char *b, *e;
} param_token;
bool extract_param(const char**, param_token*, param_token*, char, bool*);
bool parse_content_disposition(const char* hdr, char** filename);

#endif /* HTTP_HEADER_H */
