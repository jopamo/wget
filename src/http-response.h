#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stdbool.h>

struct response;

struct response* resp_new(char* head);
int resp_header_locate(const struct response* resp, const char* name, int start, const char** begptr, const char** endptr);
bool resp_header_get(const struct response* resp, const char* name, const char** begptr, const char** endptr);
bool resp_header_copy(const struct response* resp, const char* name, char* buf, int bufsize);
char* resp_header_strdup(const struct response* resp, const char* name);
int resp_status(const struct response* resp, char** message);
void resp_free(struct response** resp_ref);
void print_server_response(const struct response* resp, const char* prefix);

char* read_http_response_head(int fd);

#endif /* HTTP_RESPONSE_H */
