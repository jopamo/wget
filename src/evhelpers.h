/* Prototypes and types for the libev helper utilities
 * src/evhelpers.h
 */

#ifndef WGET_EVHELPERS_H
#define WGET_EVHELPERS_H

int wget_ev_io_wait(int fd, double maxtime, int wait_for);
void wget_ev_sleep(double seconds);

#endif /* WGET_EVHELPERS_H */
