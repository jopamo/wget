/* FTP Type Definitions
 * src/ftp-types.h
 */

#ifndef FTP_TYPES_H
#define FTP_TYPES_H

#include "wget.h"

/* System types. */
enum stype { ST_UNIX, ST_VMS, ST_WINNT, ST_MACOS, ST_OS400, ST_OTHER };

/* Extensions of the ST_UNIX */
enum ustype { UST_TYPE_L8, UST_MULTINET, UST_OTHER };

#ifdef HAVE_SSL
/* Data channel protection levels (to be used with PBSZ) */
enum prot_level { PROT_CLEAR = 'C', PROT_SAFE = 'S', PROT_CONFIDENTIAL = 'E', PROT_PRIVATE = 'P' };
#endif

/* File types.  */
enum ftype { FT_PLAINFILE, FT_DIRECTORY, FT_SYMLINK, FT_UNKNOWN };

/* Used by to test if time parsed includes hours and minutes. */
enum parsetype { TT_HOUR_MIN, TT_DAY };

/* Information about one filename in a linked list.  */
struct fileinfo {
  enum ftype type;       /* file type */
  char* name;            /* file name */
  wgint size;            /* file size */
  long tstamp;           /* time-stamp */
  enum parsetype ptype;  /* time parsing */
  int perms;             /* file permissions */
  char* linkto;          /* link to which file points */
  struct fileinfo* prev; /* previous... */
  struct fileinfo* next; /* ...and next structure. */
};

/* Commands for FTP functions.  */
enum wget_ftp_command {
  DO_LOGIN = 0x0001,     /* Connect and login to the server.  */
  DO_CWD = 0x0002,       /* Change current directory.  */
  DO_RETR = 0x0004,      /* Retrieve the file.  */
  DO_LIST = 0x0008,      /* Retrieve the directory list.  */
  LEAVE_PENDING = 0x0010 /* Do not close the socket.  */
};

enum wget_ftp_fstatus {
  NOTHING = 0x0000,     /* Nothing done yet.  */
  ON_YOUR_OWN = 0x0001, /* The ftp_loop_internal sets the
                           defaults.  */
  DONE_CWD = 0x0002,    /* The current working directory is
                           correct.  */

  /* 2013-10-17 Andrea Urbani (matfanjol)
     For more information about the following entries, please,
     look at ftp.c, function getftp, text "__LIST_A_EXPLANATION__". */
  AVOID_LIST_A = 0x0004, /* It tells us if during this
                            session we have to avoid the use
                            of "LIST -a".*/
  AVOID_LIST = 0x0008,   /* It tells us if during this
                            session we have to avoid to use
                            "LIST". */
  LIST_AFTER_LIST_A_CHECK_DONE = 0x0010,
  /* It tells us if we have already
     checked "LIST" after the first
     "LIST -a" to handle the case of
     file/folders named "-a". */
  DATA_CHANNEL_SECURITY = 0x0020 /* Establish a secure data channel */
};

#endif /* FTP_TYPES_H */