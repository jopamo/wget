/* HTTP statistics and state tracking
 * src/http-stat.h
 */
#ifndef HTTP_STAT_H
#define HTTP_STAT_H

#include "wget.h"
#include "time.h"

typedef enum {
  ENC_INVALID = -1, /* invalid encoding */
  ENC_NONE = 0,     /* no encoding */
  ENC_GZIP,         /* gzip compression */
  ENC_DEFLATE,      /* deflate compression */
  ENC_COMPRESS,     /* compress compression */
  ENC_BROTLI        /* brotli compression */
} encoding_t;

struct http_stat {
  wgint len;               /* received length */
  wgint contlen;           /* expected length */
  wgint restval;           /* the restart value */
  wgint original_restval;  /* original restart value before server ignored range */
  int res;                 /* the result of last read */
  char* rderrmsg;          /* error message from read error */
  char* newloc;            /* new location (redirection) */
  char* remote_time;       /* remote time-stamp string */
  char* error;             /* textual HTTP error */
  int statcode;            /* status code */
  char* message;           /* status message */
  wgint rd_size;           /* amount of data read from socket */
  double dltime;           /* time it took to download the data */
  const char* referer;     /* value of the referer header. */
  char* local_file;        /* local file name. */
  bool existence_checked;  /* true if we already checked for a file's
                              existence after having begun to download
                              (needed in gethttp for when connection is
                              interrupted/restarted. */
  bool timestamp_checked;  /* true if pre-download time-stamping checks
                            * have already been performed */
  char* orig_file_name;    /* name of file to compare for time-stamping
                            * (might be != local_file if -K is set) */
  wgint orig_file_size;    /* size of file to compare for time-stamping */
  time_t orig_file_tstamp; /* time-stamp of file to compare for
                            * time-stamping */

  encoding_t local_encoding;  /* the encoding of the local file */
  encoding_t remote_encoding; /* the encoding of the remote file */

  bool temporary; /* downloading a temporary file */
};

void free_hstat(struct http_stat* hs);

#endif /* HTTP_STAT_H */
