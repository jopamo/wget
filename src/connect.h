/* Establishing and handling network connections
 * src/connect.h
 */

#ifndef CONNECT_H
#define CONNECT_H

#include <stdbool.h>

#include "host.h" /* ip_address definition */

#ifdef __cplusplus
extern "C" {
#endif

/* Returned by connect_to_host when host name cannot be resolved */
enum { E_HOST = -100 };

/* Connect to a remote host name on the given TCP port
 * Returns a connected socket fd on success or E_HOST / -1 on error
 */
int connect_to_host(const char* host, int port);

/* Connect to a specific IP address on the given TCP port
 * PRINT is an optional host label used only in logs
 * Returns a connected socket fd on success or -1 on error
 */
int connect_to_ip(const ip_address* ip, int port, const char* print);

/* Create a listening socket bound to BIND_ADDRESS:*PORT
 * If *PORT is 0, the kernel chooses a port and the chosen value is
 * written back to *PORT
 * Returns a listening socket fd on success or -1 on error
 */
int bind_local(const ip_address* bind_address, int* port);

/* Accept a single incoming connection on LOCAL_SOCK
 * Returns a new connected socket fd on success or -1 on error
 */
int accept_connection(int local_sock);

/* Endpoint selector for socket_ip_address and socket_family */
enum { ENDPOINT_LOCAL, ENDPOINT_PEER };

/* Query the IP address associated with an existing connection
 * When ENDPOINT_LOCAL is used, returns the local side of the socket
 * When ENDPOINT_PEER is used, returns the remote side of the socket
 * Returns true on success, false on error
 */
bool socket_ip_address(int sock, ip_address* ip, int endpoint);

/* Return the socket family (AF_INET, AF_INET6, ...) of a connection
 * Returns the family on success or -1 on error
 */
int socket_family(int sock, int endpoint);

/* Return true if a connect error is considered retryable by the client
 * Non retryable include protocol support errors and optionally
 * connection refused / unreachable depending on opt.retry_connrefused
 */
bool retryable_socket_connect_error(int err);

/* Flags for select_fd's WAIT_FOR argument */
enum { WAIT_FOR_READ = 1, WAIT_FOR_WRITE = 2 };

/* Wait for FD to become ready for reading and/or writing
 * MAXTIME is a timeout in seconds
 * Returns 1 if ready, 0 on timeout, -1 on error
 */
int select_fd(int fd, double maxtime, int wait_for);

/* Nonblocking variant used by code that manages O_NONBLOCK explicitly
 * Semantics match select_fd, but may avoid resetting socket flags
 */
int select_fd_nb(int fd, double maxtime, int wait_for);

/* Lightweight test that a socket is still open from the client's view
 * Returns true if the connection appears open, false if it has pending
 * data or EOF/error ready to be read
 */
bool test_socket_open(int sock);

/* Transport abstraction for non plain file descriptor backends
 *
 * Implementations typically wrap an underlying socket with TLS or
 * another transport, while preserving fd oriented APIs for callers
 */
struct transport_implementation {
  /* Read at most BUF_LEN bytes into BUF
   * Returns number of bytes read, 0 on EOF, or -1 on error
   */
  int (*reader)(int fd, char* buf, int buf_len, void* ctx, double timeout);

  /* Write up to BUF_LEN bytes from BUF
   * Returns number of bytes written or -1 on error
   */
  int (*writer)(int fd, char* buf, int buf_len, void* ctx);

  /* Poll FD for readiness based on WAIT_FOR flags
   * Returns 1 if ready, 0 on timeout, -1 on error
   */
  int (*poller)(int fd, double timeout, int wait_for, void* ctx);

  /* Peek at available data without consuming it
   * Returns number of bytes that can be read, 0 on EOF, or -1 on error
   */
  int (*peeker)(int fd, char* buf, int buf_len, void* ctx, double timeout);

  /* Optional transport specific error description
   * Returns a borrowed pointer which remains valid until fd_close
   */
  const char* (*errstr)(int fd, void* ctx);

  /* Close the underlying transport and release associated state */
  void (*closer)(int fd, void* ctx);
};

/* Register a transport implementation for an existing socket like FD
 * After registration, fd_read/fd_write/fd_peek/fd_errstr/fd_close will
 * dispatch to the provided implementation when available
 */
void fd_register_transport(int fd, struct transport_implementation* imp, void* ctx);

/* Retrieve the opaque context pointer previously registered with FD
 * Returns NULL if no transport is registered
 */
void* fd_transport_context(int fd);

/* Read from FD with an optional timeout in seconds
 * If TIMEOUT is -1, opt.read_timeout will be used
 * Returns number of bytes read, 0 on EOF, or -1 on error
 */
int fd_read(int fd, char* buf, int buf_len, double timeout);

/* Write the contents of BUF to FD with an optional timeout in seconds
 * Loops until all data is written or an error occurs
 * Returns last write result, or -1 on error
 */
int fd_write(int fd, char* buf, int buf_len, double timeout);

/* Peek at pending data on FD without consuming it
 * Returns number of bytes peeked, 0 on EOF, or -1 on error
 */
int fd_peek(int fd, char* buf, int buf_len, double timeout);

/* Return a human readable error string for the most recent fd_* failure
 * May return a transport specific message or fall back to strerror(errno)
 */
const char* fd_errstr(int fd);

/* Close FD and any transport layered on top of it
 * Safe to call with a negative fd, which is ignored
 */
void fd_close(int fd);

/* Free internal connect/transport state
 * Only used in debug and test configurations
 */
#if defined DEBUG_MALLOC || defined TESTING
void connect_cleanup(void);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CONNECT_H */
