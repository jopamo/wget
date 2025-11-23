/* Libev-backed signal helpers.  */
#ifndef WGET_SIGNALS_H
#define WGET_SIGNALS_H

typedef void (*wget_signal_handler)(int signum);

void wget_signals_watch(int signum, wget_signal_handler handler);
void wget_signals_unwatch(int signum);
void wget_signals_shutdown(void);

#endif /* WGET_SIGNALS_H */
