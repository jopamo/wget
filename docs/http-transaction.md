# HTTP Transaction State Machine (`http_transaction`)

**Goal:** Manage the lifecycle of a single HTTP request and response, fully asynchronously. Each transaction handles one HTTP exchange: send request, read status, headers, body, and either succeed or fail.

## Transaction States

```c
enum http_state {
  H_INIT,
  H_RESOLVE_OR_REUSE,
  H_CONNECTING,
  H_TLS_HANDSHAKE,
  H_SEND_REQUEST,
  H_READ_STATUS_LINE,
  H_READ_HEADERS,
  H_READ_BODY,
  H_COMPLETED,
  H_FAILED
};
```

* `H_INIT`: Created, no connection yet.
* `H_RESOLVE_OR_REUSE`: Try to reuse a pooled connection or create a new one.
* `H_CONNECTING`: Waiting for `net_conn` to become ready.
* `H_TLS_HANDSHAKE`: Optional explicit state (may be merged with `H_CONNECTING`).
* `H_SEND_REQUEST`: Serialize and send HTTP request.
* `H_READ_STATUS_LINE`: Read and parse the status line.
* `H_READ_HEADERS`: Read and parse headers.
* `H_READ_BODY`: Stream body to output.
* `H_COMPLETED`: Successful completion.
* `H_FAILED`: Error.

## Request/Response Structures

```c
struct http_request {
  char *url;
  char *method;
  char *host;
  char *path;
  char *headers;  // serialized headers or vector of lines
  // port, use_tls, body, etc
};

struct http_response {
  int status_code;
  char *status_line;
  struct header_list *headers;
  // cached flags: content_length, chunked, gzip, etc
};
```

## Transaction Structure

```c
struct http_transaction {
  enum http_state state;

  struct http_request *req;
  struct http_response *resp;
  struct net_conn *conn;
  struct evloop_timer *timeout_timer;

  char *recv_buffer;
  size_t recv_buffer_size;
  size_t recv_buffer_used;

  size_t content_length;
  bool chunked;
  bool gzip;

  // chunk decoder state
  size_t chunk_bytes_remaining;
  // decompression state if needed

  void *output_sink;   // FILE*, WARC writer, etc

  int retries;         // optional
  // other fields...
};
```

## Connection Acquisition

In `H_RESOLVE_OR_REUSE`:

* Call `pconn_acquire(evloop, scheme, host, port, use_tls)`.

  * If an idle connection is returned (already ready), attach it and jump directly to `H_SEND_REQUEST`.
  * If a new connection is created, transaction enters `H_CONNECTING` and waits for `net_conn` callbacks.

`net_conn` callbacks for this transaction:

```c
void http_transaction_conn_ready(struct net_conn *c, void *arg);
void http_transaction_conn_error(struct net_conn *c, void *arg);
```

* `conn_ready`:

  * Attach `c` to `txn->conn`.
  * Set `txn->state = H_SEND_REQUEST`.
  * Register readable/writable callbacks:

    ```c
    conn_set_readable_callback(c, http_transaction_can_read, txn);
    conn_set_writable_callback(c, http_transaction_can_write, txn);
    ```
  * Start sending request.

* `conn_error`:

  * Set `state = H_FAILED`.
  * Notify scheduler for retry or final failure.

## Sending the Request (`H_SEND_REQUEST`)

* Serialize HTTP request into a buffer:

  ```
  GET /path HTTP/1.1\r\n
  Host: example.com\r\n
  User-Agent: ...\r\n
  [other headers]\r\n
  \r\n
  [optional body]
  ```

* Maintain an offset of bytes written so far.

`http_transaction_can_write(struct net_conn *c, void *arg)`:

* Attempt to send remaining bytes via `conn_try_write`.
* On partial write, keep `EV_WRITE` enabled.
* When fully sent:

  * Disable `EV_WRITE` (or clear writable callback).
  * Set `state = H_READ_STATUS_LINE`.
  * Make sure `EV_READ` is enabled (readable callback registered).
  * Start header timeout timer.

## Reading Status Line (`H_READ_STATUS_LINE`)

`http_transaction_can_read(struct net_conn *c, void *arg)`:

* If `state == H_READ_STATUS_LINE`:

  * Append data from `conn_try_read()` into `recv_buffer`.
  * Search for first `"\r\n"`.

    * If found:

      * Extract status line, parse `HTTP/<version> <status> <reason>`.
      * Store in `resp`.
      * Remove consumed bytes (or move offset).
      * `state = H_READ_HEADERS`.
    * If not found, keep waiting for more data.

## Reading Headers (`H_READ_HEADERS`)

* Continue reading into buffer.
* Search for header terminator `"\r\n\r\n"`.

When found:

* Split out headers section.
* Parse line-by-line into `resp->headers`.
* Detect:

  * `Content-Length: N`
  * `Transfer-Encoding: chunked`
  * `Content-Encoding: gzip` (or deflate)
  * `Connection: close` / keep-alive
* Configure body processing:

  * Set `content_length`, `chunked`, `gzip`, etc.
* `state = H_READ_BODY`.
* Any bytes after `\r\n\r\n` are the beginning of the body; process immediately with body logic.

If not found, continue to accumulate.

## Reading Body (`H_READ_BODY`)

Body handling depends on headers:

* **Fixed `Content-Length`**:

  * Track `body_bytes_remaining`.
  * Each read:

    * Write data to `output_sink`.
    * Decrement `body_bytes_remaining`.
  * When reaches 0 → body done → `H_COMPLETED`.

* **Chunked Transfer-Encoding**:

  * Implement a chunk decoder that:

    * Reads a chunk-size line (hex number + CRLF).
    * Reads exactly that many bytes as chunk data.
    * Consumes CRLF after each chunk.
    * Terminates on a zero-length chunk plus trailing headers.
  * As each chunk's data arrives, write it to `output_sink`.
  * Once the terminating chunk is processed, body done → `H_COMPLETED`.

* **Connection-close delimited**:

  * No `Content-Length`, no `chunked`.
  * Read until EOF (`conn_try_read` returns 0).
  * Stream data to `output_sink` as it arrives.
  * On EOF, treat as completion unless protocol says otherwise.

* **Compressed body** (`gzip`/`deflate`):

  * Feed the raw body bytes into a zlib inflate stream.
  * Write decompressed bytes to `output_sink`.
  * This can combine with chunked encoding (decode framing first, then decompress chunk payloads).

For each read:

* On I/O error or malformed data, `H_FAILED`.
* Inactivity timeout via `timeout_timer` can abort if no data arrives for too long.

## Completion and Failure

* **On `H_COMPLETED`**:

  * Inform scheduler.
  * Decide whether connection is reusable (`keep_alive_ok`):

    * No `Connection: close`,
    * No protocol errors,
    * Not close-delimited by peer closing unexpectedly.
  * Call `pconn_release(conn, keep_alive_ok)`:

    * If reusable, it enters pool.
    * Otherwise, closed.
  * Free transaction state, close output file, etc.

* **On `H_FAILED`**:

  * Ensure connection is not reused:

    * Close it, or call `pconn_release(conn, false)`.
  * Notify scheduler for retry or final failure.
  * Free transaction resources.

The HTTP state machine progresses via callbacks:

* `http_transaction_conn_ready` / `_conn_error`
* `http_transaction_can_write`
* `http_transaction_can_read`
* Timeout callbacks from timers

Each callback does bounded work and yields back to the loop.