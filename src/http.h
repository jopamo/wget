/* Declarations for HTTP.
 * src/http.h
 *
 * Copyright (C) 2005-2011, 2015, 2018-2024 Free Software Foundation,
 * Inc.
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
 *
 * Additional permission under GNU GPL version 3 section 7
 *
 * If you modify this program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
 * grants you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#ifndef HTTP_H
#define HTTP_H

#include "hsts.h"
#include "transfer.h"
#include "http_body.h"  // For http_body_done_cb

struct url;
struct request;
struct http_stat;
struct iri;
struct ip_address;

typedef enum {
  HLS_INIT = 0,
  HLS_ESTABLISH_CONNECTION,
  HLS_SEND_REQUEST,
  HLS_READ_RESPONSE_HEADERS,
  HLS_READ_BODY_UNAUTHORIZED,
  HLS_READ_BODY_REDIRECTED,
  HLS_READ_BODY_ERROR,
  HLS_READ_BODY_MAIN,
  HLS_COMPLETED,
  HLS_FAILED
} http_transaction_state;

struct http_transaction_ctx {
  http_transaction_state state;
  const struct url* u;
  struct url* original_url;
  char** newloc;
  char** local_file;
  const char* referer;
  int* dt;
  struct url* proxy;
  struct iri* iri;
  struct transfer_context* tctx;
  int count;  // retry count

  // Variables from original gethttp
  struct request* req;
  char* type;
  char *user, *passwd;
  char* proxyauth;
  int statcode;
  int write_error;
  wgint contlen, contrange;
  const struct url* conn;
  FILE* fp;
  int err;
  uerr_t retval;
  int sock;
  bool auth_finished;
  bool basic_auth_finished;
  bool ntlm_seen;
  bool using_ssl;
  bool head_only;
  bool cond_get;
  char* head;
  struct http_response* resp;
  char hdrval[512];
  char* message;
  bool warc_enabled;
  FILE* warc_tmp;
  char warc_timestamp_str[21];
  char warc_request_uuid[48];
  ip_address warc_ip_buf, *warc_ip;
  off_t warc_payload_offset;
  bool keep_alive;
  bool chunked_transfer_encoding;
  bool inhibit_keep_alive;
  wgint body_data_size;
  struct http_stat hstat;  // HTTP status

  // Callback to signal completion of the async operation
  void (*final_cb)(struct http_transaction_ctx* ctx, uerr_t status);
};

// Asynchronous HTTP transaction function
struct http_transaction_ctx* http_loop_start_async(const struct url* u,
                                                   struct url* original_url,
                                                   char** newloc,
                                                   char** local_file,
                                                   const char* referer,
                                                   int* dt,
                                                   struct url* proxy,
                                                   struct iri* iri,
                                                   struct transfer_context* tctx,
                                                   void (*final_cb)(struct http_transaction_ctx* ctx, uerr_t status));
void http_loop_continue_async(struct http_transaction_ctx* ctx, uerr_t prev_op_status);
void http_loop_cleanup(struct http_transaction_ctx* ctx);
void http_cleanup(void);

#endif /* HTTP_H */
