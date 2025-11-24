/* Declarations for retr.c.
 * src/retr.h
 *
 * Copyright (C) 1996-2011, 2015, 2018-2024 Free Software Foundation,
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

#ifndef RETR_H
#define RETR_H

#include "url.h"
#include "transfer.h"

struct ev_loop;

/* Document type flags used in http_loop and elsewhere. */
#define RETROKF 0x0001              /* retrieval was OK */
#define TEXTHTML 0x0002             /* document is of type text/html */
#define TEXTCSS 0x0004              /* document is of type text/css */
#define BINARY 0x0008               /* don't convert line endings */
#define ADDED_HTML_EXTENSION 0x0010 /* local filename has ".html" appended */
#define HEAD_ONLY 0x0020            /* only headers were retrieved */
#define SEND_NOCACHE 0x0040         /* send Pragma: no-cache / Cache-Control: no-cache */
#define IF_MODIFIED_SINCE 0x0080    /* send If-Modified-Since header */
#define TEXTXML 0x0100              /* document is of type text/xml */
#define APPXML 0x0200               /* document is of type application/xml */

extern int numurls;

/* These global vars should be made static to retr.c and exported via
   functions! */
extern wgint total_downloaded_bytes;
extern double total_download_time;
extern FILE* output_stream;
extern bool output_stream_regular;

/* Flags for fd_read_body. */
enum {
  rb_read_exactly = 1,
  rb_skip_startpos = 2,

  /* Used by HTTP/HTTPS*/
  rb_chunked_transfer_encoding = 4,

  rb_compressed_gzip = 8
};

typedef const char* (*hunk_terminator_t)(const char*, const char*, int);

char* fd_read_hunk(int, hunk_terminator_t, long, long);
char* fd_read_line(int);

typedef void (*retr_body_done_cb)(int status, wgint qtyread, wgint qtywritten, double elapsed, void* user_data);
int retr_body_start_async(struct ev_loop* loop,
                          const char* downloaded_filename,
                          int fd,
                          FILE* out,
                          wgint toread,
                          wgint startpos,
                          wgint* qtyread,
                          wgint* qtywritten,
                          double* elapsed,
                          int flags,
                          FILE* out2,
                          retr_body_done_cb done_cb,
                          void* user_data);

uerr_t retrieve_url(struct url*, const char*, char**, char**, const char*, int*, bool, struct iri*, bool, struct transfer_context*);

typedef enum { RURL_STATE_INIT, RURL_STATE_HTTP_LOOP, RURL_STATE_REDIRECT, RURL_STATE_COMPLETED, RURL_STATE_FAILED } retrieve_url_state;

struct retrieve_url_ctx {
  uerr_t result;
  struct url *u, *original_url, *proxy_url;
  char **newloc, **local_file;
  const char* referer;
  int* dt;
  bool dt_passed_in;  // To track if dt was passed in or allocated internally
  struct iri* iri;
  struct transfer_context* tctx;
  void (*final_cb)(struct retrieve_url_ctx* ctx);
  int redirect_count;
  struct http_transaction_ctx* http_ctx;  // Changed from http_loop_ctx
  retrieve_url_state state;
  char* url;                  // For current URL string
  char* proxy;                // For current proxy string
  int up_error_code;          // Changed from uerr_t to int
  bool initial_url_parsed;    // To track if the initial URL is parsed
  bool free_orig_parsed_url;  // To track if orig_parsed_url needs to be freed
};

struct retrieve_url_ctx* retrieve_url_start_async(struct url* u,
                                                  const char* url_str,
                                                  char** newloc,
                                                  char** file,
                                                  const char* referer,
                                                  int* dt,
                                                  bool recursive,
                                                  struct iri* iri,
                                                  bool initial_url_parsed,
                                                  struct transfer_context* tctx,
                                                  void (*final_cb)(struct retrieve_url_ctx* ctx));
void retrieve_url_continue_async(struct retrieve_url_ctx* ctx, uerr_t prev_op_status);
uerr_t retrieve_from_file(const char*, bool, int*);

// Asynchronous retrieve_from_url_list context
typedef enum { RURL_LIST_STATE_INIT, RURL_LIST_STATE_RETRIEVING_URL, RURL_LIST_STATE_COMPLETED, RURL_LIST_STATE_FAILED } retrieve_from_url_list_state;

struct retrieve_from_url_list_ctx {
  uerr_t result;
  struct urlpos* url_list;
  struct urlpos* current_url_pos;
  int* count;  // Pointer to the count in the caller
  struct iri* iri;
  void (*final_cb)(struct retrieve_from_url_list_ctx* ctx);
  struct retrieve_url_ctx* rurl_ctx;  // Current retrieve_url context
  retrieve_from_url_list_state state;
};

struct retrieve_from_url_list_ctx* retrieve_from_url_list_start_async(struct urlpos* url_list, int* count, struct iri* iri, void (*final_cb)(struct retrieve_from_url_list_ctx* ctx));
void retrieve_from_url_list_continue_async(struct retrieve_from_url_list_ctx* ctx, uerr_t prev_op_status);

// Asynchronous retrieve_from_file context
typedef enum { RFILE_STATE_INIT, RFILE_STATE_FETCH_URL_FILE, RFILE_STATE_GET_URLS_FROM_FILE, RFILE_STATE_RETRIEVING_URL_LIST, RFILE_STATE_COMPLETED, RFILE_STATE_FAILED } retrieve_from_file_state;

struct retrieve_from_file_ctx {
  uerr_t result;
  const char* file;
  bool html;
  int* count;  // Pointer to the count in the caller
  struct iri* iri;
  void (*final_cb)(struct retrieve_from_file_ctx* ctx);
  char* input_file;           // Can be a local file path or a downloaded temp file
  char* url_file_downloaded;  // Path to the downloaded URL file
  int up_error_code;
  struct url* url_parsed;
  bool is_url_input_file;                            // Whether the input 'file' parameter was actually a URL
  struct retrieve_url_ctx* rurl_file_ctx;            // Context for downloading the input file if it's a URL
  struct retrieve_from_url_list_ctx* rurl_list_ctx;  // Context for retrieving the URL list
  bool read_again;
  struct main_loop_ctx* main_ctx;  // Pointer to the main loop context
  retrieve_from_file_state state;
};

struct retrieve_from_file_ctx* retrieve_from_file_start_async(const char* file, bool html, int* count, void (*final_cb)(struct retrieve_from_file_ctx* ctx));
void retrieve_from_file_continue_async(struct retrieve_from_file_ctx* ctx, uerr_t prev_op_status);

const char* retr_rate(wgint, double);
double calc_rate(wgint, double, int*);
void printwhat(int, int);

int sleep_between_retrievals_async(struct scheduler* sched, int count, void (*callback)(void*), void* user_arg);

void rotate_backups(const char*);

bool url_uses_proxy(struct url*);

void set_local_file(const char**, const char*);

bool input_file_url(const char*);

#endif /* RETR_H */
