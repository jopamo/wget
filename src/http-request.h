#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <stdio.h>
#include <stdbool.h>

/* Release policy for header values. */
enum rp { rel_none, rel_name, rel_value, rel_both };

struct request;

struct request* request_new(const char* method, char* arg);
const char* request_method(const struct request* req);
void request_set_header(struct request* req, const char* name, const char* value, enum rp release_policy);
void request_set_user_header(struct request* req, const char* header);
void request_set_user_agent(struct request* req);
bool request_remove_header(struct request* req, const char* name);
int request_send(const struct request* req, int fd, FILE* warc_tmp);
void request_free(struct request** req_ref);

#endif /* HTTP_REQUEST_H */
