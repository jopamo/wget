/* FTP Command Processing
 * src/ftp-commands.h
 */

#ifndef FTP_COMMANDS_H
#define FTP_COMMANDS_H

#include "wget.h"
#include "url.h"
#include "host.h"
#include "ftp-types.h"

/* FTP command execution functions */
uerr_t ftp_execute_command(int csock, const char* command, const char* value);
uerr_t ftp_send_command(int csock, const char* command, const char* value);
uerr_t ftp_read_response(int csock, char** response);

/* Basic FTP commands */
uerr_t ftp_command_user(int csock, const char* username);
uerr_t ftp_command_pass(int csock, const char* password);
uerr_t ftp_command_syst(int csock, enum stype* server_type, enum ustype* unix_type);
uerr_t ftp_command_pwd(int csock, char** pwd);
uerr_t ftp_command_type(int csock, char type_char);
uerr_t ftp_command_cwd(int csock, const char* dir);
uerr_t ftp_command_rest(int csock, wgint offset);
uerr_t ftp_command_retr(int csock, const char* file);
uerr_t ftp_command_list(int csock, const char* file, bool avoid_list_a, bool avoid_list, bool* list_a_used);
uerr_t ftp_command_size(int csock, const char* file, wgint* size);

/* Data connection commands */
uerr_t ftp_command_pasv(int csock, ip_address* addr, int* port);
uerr_t ftp_command_port(int csock, int* local_sock);
uerr_t ftp_do_pasv(int csock, ip_address* addr, int* port);
uerr_t ftp_do_port(int csock, int* local_sock);

/* IPv6 extensions */
uerr_t ftp_command_epsv(int csock, ip_address* ip, int* port);
uerr_t ftp_command_eprt(int csock, int* local_sock);
uerr_t ftp_command_lpsv(int csock, ip_address* addr, int* port);
uerr_t ftp_command_lprt(int csock, int* local_sock);

/* Security extensions */
uerr_t ftp_command_auth(int csock, enum url_scheme scheme);
uerr_t ftp_command_pbsz(int csock, int pbsz);
uerr_t ftp_command_prot(int csock, enum prot_level prot);

/* Command validation and processing */
char ftp_process_type(const char* params);

#endif /* FTP_COMMANDS_H */