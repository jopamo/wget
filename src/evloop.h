/* Interfaces for the central libev event loop
 * src/evloop.h
 */

#ifndef WGET_EVLOOP_H
#define WGET_EVLOOP_H

#include <stdbool.h>

#if defined HAVE_PTHREAD_H && HAVE_PTHREAD_H
#define WGET_EVLOOP_CONTINUOUS 1
#else
#define WGET_EVLOOP_CONTINUOUS 0
#endif

struct ev_loop;

typedef void (*wget_ev_loop_async_cb)(void*);

void wget_ev_loop_init(void);
void wget_ev_loop_deinit(void);
struct ev_loop* wget_ev_loop_get(void);
void wget_ev_loop_run(void);
void wget_ev_loop_run_once(void);
void wget_ev_loop_break(void);
void wget_ev_loop_wakeup(void);
bool wget_ev_loop_is_initialized(void);
void wget_ev_loop_transfer_ref(void);
void wget_ev_loop_transfer_unref(void);
bool wget_ev_loop_has_active_transfers(void);
bool wget_ev_loop_post_async(wget_ev_loop_async_cb cb, void* arg);

#endif /* WGET_EVLOOP_H */
