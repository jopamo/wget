/* FTP File Retrieval Operations
 * src/ftp-retrieve.h
 */

#ifndef FTP_RETRIEVE_H
#define FTP_RETRIEVE_H

#include "wget.h"
#include "url.h"
#include "ftp-types.h"

/* File retrieval context structure */
typedef struct {
  struct url* u;            /* target URL */
  struct url* original_url; /* original URL (for redirects) */
  wgint expected_bytes;     /* expected file size */
  wgint restval;            /* restart position */
  wgint qtyread;            /* bytes actually read */
  bool got_expected_bytes;  /* whether size was obtained */
  bool rest_failed;         /* whether restart failed */
  char type_char;           /* transfer type character */
} ftp_retrieve_ctx_t;

/* High-level file retrieval functions */
uerr_t
ftp_retrieve_file(struct url* u, struct url* original_url, wgint passed_expected_bytes, wgint* qtyread, wgint restval, ftp_session_t* session, int count, wgint* last_expected_bytes, FILE* warc_tmp);

uerr_t ftp_retrieve_single_file(struct url* u, struct url* original_url, struct fileinfo* f, ftp_session_t* session, char** local_file, bool force_full_retrieve);

/* File retrieval loop management */
uerr_t ftp_retrieve_loop_internal(struct url* u, struct url* original_url, struct fileinfo* f, ftp_session_t* session, char** local_file, bool force_full_retrieve);

/* File retrieval state management */
uerr_t ftp_retrieve_init_context(ftp_retrieve_ctx_t* ctx, struct url* u, struct url* original_url, wgint passed_expected_bytes, wgint restval);
uerr_t ftp_retrieve_cleanup_context(ftp_retrieve_ctx_t* ctx);

/* File size and restart operations */
uerr_t ftp_retrieve_get_file_size(int csock, const char* filename, wgint* size);
uerr_t ftp_retrieve_set_restart_position(int csock, wgint restval);

/* File transfer operations */
uerr_t ftp_retrieve_initiate_transfer(int csock, const char* filename);
uerr_t ftp_retrieve_complete_transfer(int csock, wgint* last_expected_bytes);

/* File retrieval validation */
uerr_t ftp_retrieve_validate_file(struct fileinfo* f, const char* local_file, bool* should_download, bool* force_full_retrieve);

/* File retrieval utilities */
uerr_t ftp_retrieve_prepare_local_file(const char* local_file, wgint restval, int cmd_flags, char type_char, FILE** fp);
uerr_t ftp_retrieve_finalize_local_file(const char* local_file, struct fileinfo* f, bool downloaded, wgint qtyread);

#endif /* FTP_RETRIEVE_H */