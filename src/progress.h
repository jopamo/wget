/* Download progress
 * src/progress.h
 */

#ifndef PROGRESS_H
#define PROGRESS_H

#include <ev.h>

bool valid_progress_implementation_p(const char*);
void set_progress_implementation(const char*);
void progress_schedule_redirect(void);

void* progress_create(const char*, wgint, wgint);
bool progress_interactive_p(void*);
void progress_update(void*, wgint, double);
void progress_finish(void*, double);

void progress_handle_sigwinch(int);

/* libev integration */
void progress_init(struct ev_loop*);
void progress_shutdown(void);

#endif /* PROGRESS_H */
