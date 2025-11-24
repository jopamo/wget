/* Prototypes and types for the libev helper utilities
 * src/evhelpers.h
 */

#ifndef WGET_EVHELPERS_H
#define WGET_EVHELPERS_H

/* LEGACY_BLOCKING: synchronous wait on a single fd. */
int wget_ev_io_wait(int fd, double maxtime, int wait_for);
/* LEGACY_BLOCKING: synchronous timer helper. */
void wget_ev_sleep(double seconds);

#endif /* WGET_EVHELPERS_H */
