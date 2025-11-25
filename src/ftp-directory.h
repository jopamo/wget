/* FTP Directory Navigation and Listing
 * src/ftp-directory.h
 */

#ifndef FTP_DIRECTORY_H
#define FTP_DIRECTORY_H

#include "wget.h"
#include "url.h"
#include "ftp-types.h"

/* Directory navigation context structure */
typedef struct {
  char* initial_dir;      /* initial directory from PWD command */
  char* current_dir;      /* current working directory */
  char* target_dir;       /* target directory for operations */
  enum stype server_type; /* remote system type */
  enum ustype unix_type;  /* UNIX system subtype */
  bool avoid_list_a;      /* whether to avoid LIST -a */
  bool avoid_list;        /* whether to avoid LIST command */
  bool list_a_check_done; /* whether LIST -a check completed */
  int cwd_flags;          /* CWD operation flags */
} ftp_directory_ctx_t;

/* Directory listing operations */
uerr_t ftp_directory_get_listing(struct url* u, struct url* original_url, ftp_session_t* session, struct fileinfo** f);
uerr_t ftp_directory_parse_listing(const char* listing_file, enum stype system_type, struct fileinfo** f);

/* Directory navigation functions */
uerr_t ftp_directory_change(ftp_session_t* session, const char* dir);
uerr_t ftp_directory_get_current(ftp_session_t* session, char** pwd);
uerr_t ftp_directory_validate_path(const char* path, enum stype system_type);

/* Directory traversal for recursive downloads */
uerr_t ftp_directory_traverse(struct url* u, struct url* original_url, struct fileinfo* f, ftp_session_t* session);
uerr_t ftp_directory_process_dirs(struct url* u, struct url* original_url, struct fileinfo* f, ftp_session_t* session);

/* Directory name validation and security */
bool ftp_directory_has_insecure_name(const char* name);
bool ftp_directory_is_valid_entry(struct fileinfo* f, struct fileinfo* start);

/* Directory globbing and pattern matching */
uerr_t ftp_directory_glob_files(struct url* u, struct url* original_url, ftp_session_t* session, int action);
struct fileinfo* ftp_directory_filter_entries(struct fileinfo* start, const char* pattern, bool ignore_case);

/* Directory context management */
uerr_t ftp_directory_init_context(ftp_directory_ctx_t* ctx, enum stype system_type);
uerr_t ftp_directory_cleanup_context(ftp_directory_ctx_t* ctx);

#endif /* FTP_DIRECTORY_H */