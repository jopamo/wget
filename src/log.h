/* Declarations for log.c
 * src/log.h
 */

#ifndef LOG_H
#define LOG_H

/* The log file to which Wget writes to after HUP.  */
#define DEFAULT_LOGFILE "wget-log"

#include <stdio.h>

enum log_options { LOG_VERBOSE, LOG_NOTQUIET, LOG_NONVERBOSE, LOG_ALWAYS, LOG_PROGRESS };

void log_set_warc_log_fp(FILE*);

void logprintf(enum log_options, const char*, ...) GCC_FORMAT_ATTR(2, 3);
void debug_logprintf(const char*, ...) GCC_FORMAT_ATTR(1, 2);
void logputs(enum log_options, const char*);
void logflush(void);
void log_set_flush(bool);
bool log_set_save_context(bool);

void log_init(const char*, bool);
void log_close(void);
void log_cleanup(void);
void log_request_redirect_output(const char*);
void redirect_output(bool, const char*);

const char* escnonprint(const char*);
const char* escnonprint_uri(const char*);

#endif /* LOG_H */
