/* Interfaces for the central libev event loop
 * src/evloop.h
 */

#ifndef WGET_EVLOOP_H
#define WGET_EVLOOP_H

#include <stdbool.h>

struct ev_loop;

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
void wget_ev_loop_run_transfers(void);

#endif /* WGET_EVLOOP_H */
