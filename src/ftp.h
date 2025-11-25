/* Declarations for FTP support.
   Copyright (C) 1996-2011, 2015, 2018-2024 Free Software Foundation,
   Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */

#ifndef FTP_H
#define FTP_H

#include <stdio.h>
#include <stdbool.h>

#include "host.h"
#include "url.h"

/* FTP type definitions */
#include "ftp-types.h"

/* Modular FTP headers */
#include "ftp-session.h"
#include "ftp-commands.h"
#include "ftp-data.h"
#include "ftp-retrieve.h"
#include "ftp-directory.h"
#include "ftp-auth.h"
#include "ftp-utils.h"

uerr_t ftp_response(int, char**);
uerr_t ftp_greeting(int);
uerr_t ftp_login(int, const char*, const char*);
uerr_t ftp_port(int, int*);
uerr_t ftp_pasv(int, ip_address*, int*);
#ifdef HAVE_SSL
uerr_t ftp_auth(int, enum url_scheme);
uerr_t ftp_pbsz(int, int);
uerr_t ftp_prot(int, enum prot_level);
#endif
#ifdef ENABLE_IPV6
uerr_t ftp_lprt(int, int*);
uerr_t ftp_lpsv(int, ip_address*, int*);
uerr_t ftp_eprt(int, int*);
uerr_t ftp_epsv(int, ip_address*, int*);
#endif
uerr_t ftp_type(int, int);
uerr_t ftp_cwd(int, const char*);
uerr_t ftp_retr(int, const char*);
uerr_t ftp_rest(int, wgint);
uerr_t ftp_list(int, const char*, bool, bool, bool*);
uerr_t ftp_syst(int, enum stype*, enum ustype*);
uerr_t ftp_pwd(int, char**);
uerr_t ftp_size(int, const char*, wgint*);

#ifdef ENABLE_OPIE
const char* skey_response(int, const char*, const char*);
#endif

struct url;

struct fileinfo* ftp_parse_ls(const char*, const enum stype);
struct fileinfo* ftp_parse_ls_fp(FILE*, const enum stype);
void freefileinfo(struct fileinfo*);
uerr_t ftp_loop(struct url*, struct url*, char**, int*, struct url*, bool, bool);

uerr_t ftp_index(const char*, struct url*, struct fileinfo*);

char ftp_process_type(const char*);

#endif /* FTP_H */
