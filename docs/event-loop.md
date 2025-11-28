# Core Event Loop Abstraction (`evloop`)

**Status Note**: This component is **IMPLEMENTED AND OPERATIONAL**. The event loop abstraction provides a unified interface to libev for all async operations.

**Goal:** Provide a unified interface to the event loop so that the rest of the code remains largely agnostic of the underlying event library (libev). All modules will use this interface to register for I/O events, timers, and cross-thread wake-ups. By centralizing event management, we ensure consistent behavior and easier maintenance.

## Responsibilities and Implementation Steps

### Initialize the Event Loop

Set up a global `struct ev_loop *` (using `ev_default_loop(0)` or similar). This is done once at program start. All modules will use this single loop instance (no separate threads for now, though libev can handle signals and async from threads).

### Event Watcher Wrappers

Create lightweight wrapper structures for libev watchers so other code doesn't directly handle libev types:

```c
struct evloop_io {
  ev_io io;
  // user callback, fd, arg, etc
};

struct evloop_timer {
  ev_timer timer;
  // user callback, arg, etc
};
```

Possibly also an internal `ev_async` watcher for cross-thread or signal notifications.

### Define Callback Types

In `evloop.h`, define function pointer types for callbacks:

```c
typedef void (*ev_io_cb_t)(int fd, int revents, void *arg);
typedef void (*ev_timer_cb_t)(void *arg);
```

These represent callbacks for I/O events (read/write) and timer events, respectively. Callbacks will receive a user-provided context (`arg`) to operate on.

### Public API Functions

Provide functions to start, update, and stop watchers without exposing libev details:

```c
struct ev_loop *evloop_get_default(void);

struct evloop_io *evloop_io_start(struct ev_loop *loop, int fd, int events,
                                  ev_io_cb_t cb, void *arg);
void evloop_io_update(struct evloop_io *io, int events);
void evloop_io_stop(struct evloop_io *io);

struct evloop_timer *evloop_timer_start(struct ev_loop *loop, double after,
                                        double repeat, ev_timer_cb_t cb, void *arg);
void evloop_timer_reschedule(struct evloop_timer *t, double after, double repeat);
void evloop_timer_stop(struct evloop_timer *t);

void evloop_run(struct ev_loop *loop);
void evloop_break(struct ev_loop *loop);
```

* `evloop_io_start`: Start watching a file descriptor `fd` for the specified events (readable or writable, e.g. `EV_READ` and/or `EV_WRITE`). When the event triggers, call the provided `cb(fd, events, arg)`.
* `evloop_io_update`: Change the events (read/write) to watch on an active watcher.
* `evloop_io_stop`: Stop and free an I/O watcher.
* `evloop_timer_start`: Start a one-shot or repeating timer (`after` seconds for first trigger, optional `repeat` interval).
* `evloop_timer_reschedule`: Adjust an existing timer to new values.
* `evloop_timer_stop`: Stop and free a timer.
* `evloop_run`: Enter the event loop (calls `ev_run(loop, 0)` internally).
* `evloop_break`: Safely break out of the loop, causing `evloop_run` to return.

Internally, these functions will allocate the appropriate libev watcher (`ev_io` or `ev_timer`), set the callback to a static function that unpacks the user arg and invokes the user-provided callback, and start/stop the watcher via libev API. No other part of the program should call `ev_io_start` or other libev functions directly – this ensures libev usage is centralized.

### Async and Signal Handling

Use `ev_async` watchers for two purposes:

* **Cross-thread notifications**: If some other thread needs to signal the event loop (e.g., adding a new task from a different thread), `ev_async_send` can wake the loop and invoke a callback to handle the new task. Initialize an `ev_async` in `evloop` that breaks the loop or processes a cross-thread events queue.
* **Signal handling**: Libev can integrate with OS signals via `ev_signal`. We can set up signal watchers (like `SIGINT` or `SIGTERM`). For example, on `SIGINT`, schedule a graceful shutdown by stopping ongoing tasks or breaking the loop.

### Thread-Safety

The core event loop runs in a single thread (the main thread in our design). Other threads should not manipulate libev directly. If other threads must influence the loop, they should use the `ev_async` mechanism to marshal work into the loop thread. The provided functions are generally called from within the loop thread, so they are safe.

### One-time Initialization

`evloop_get_default()` can create and return the global loop (singleton). We call this during startup (in `main` or in scheduler init) and pass the loop pointer to other modules as needed.

By implementing `evloop.c/.h` first, we set the foundation for all other components to register events without worrying about the details of libev.