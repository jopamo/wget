/* HTTP request helpers.
 * src/http_request.h
 *
 * Copyright (C) 2024 Free Software
 * Foundation, Inc.
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

#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <stdbool.h>
#include <stdio.h>

struct request;

enum rp {
  rel_none,
  rel_name,
  rel_value,
  rel_both
};

struct request* request_new(const char* method, char* arg);
const char* request_method(const struct request* req);
void request_set_header(struct request* req, const char* name, const char* value, enum rp release_policy);
void request_set_user_header(struct request* req, const char* header);
bool request_remove_header(struct request* req, const char* name);
int request_send(const struct request* req, int fd, FILE* warc_tmp);
void request_free(struct request** req_ref);

#endif /* HTTP_REQUEST_H */
