/* FTP Utility Functions and Common Operations
 * src/ftp-utils.h
 */

#ifndef FTP_UTILS_H
#define FTP_UTILS_H

#include "wget.h"
#include "url.h"
#include "ftp-types.h"

/* File information operations */
struct fileinfo* ftp_utils_create_fileinfo(const char* name, enum ftype type, wgint size, time_t tstamp, mode_t perms);
uerr_t ftp_utils_free_fileinfo(struct fileinfo* f);
uerr_t ftp_utils_free_fileinfo_list(struct fileinfo* f);
struct fileinfo* ftp_utils_delete_fileinfo_element(struct fileinfo** f, struct fileinfo** start);

/* File size and type operations */
wgint ftp_utils_parse_expected_bytes(const char* response);
char ftp_utils_process_transfer_type(const char* params);
uerr_t ftp_utils_print_file_length(wgint size, wgint start, bool authoritative);

/* Local file operations */
uerr_t ftp_utils_prepare_local_file(const char* local_file, wgint restval, int cmd_flags, char type_char, FILE** fp);
uerr_t ftp_utils_finalize_local_file(const char* local_file, struct fileinfo* f, bool downloaded, wgint qtyread);
uerr_t ftp_utils_set_file_permissions(const char* local_file, mode_t perms);
uerr_t ftp_utils_set_file_timestamp(const char* local_file, time_t tstamp);

/* URL and path operations */
char* ftp_utils_build_target_filename(struct url* u, struct url* original_url);
char* ftp_utils_merge_directory_path(const char* base, const char* subdir);
uerr_t ftp_utils_validate_url_path(struct url* u);

/* Error handling and logging */
uerr_t ftp_utils_print_retry_message(int count, int max_tries);
const char* ftp_utils_error_string(uerr_t err);
uerr_t ftp_utils_handle_common_errors(uerr_t err, int* should_retry);

/* Connection utilities */
uerr_t ftp_utils_get_server_greeting(int csock);
uerr_t ftp_utils_get_system_type(int csock, enum stype* server_type, enum ustype* unix_type);
uerr_t ftp_utils_set_transfer_type(int csock, char type_char);

/* Security utilities */
bool ftp_utils_is_secure_scheme(enum url_scheme scheme);
uerr_t ftp_utils_validate_security_options(struct url* u);

/* Progress and statistics */
uerr_t ftp_utils_update_download_stats(wgint bytes_downloaded, double download_time);
const char* ftp_utils_format_download_rate(wgint bytes, double seconds);

#endif /* FTP_UTILS_H */